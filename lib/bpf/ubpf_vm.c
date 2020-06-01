/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <timeval.h>
#include "ubpf_int.h"
#include <config.h>
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "util.h"


#define MAX_EXT_FUNCS 64
#define MAX_EXT_MAPS 64
#define NB_REGS 11

VLOG_DEFINE_THIS_MODULE(verifier);
// #define DEBUG(...) VLOG_INFO(__VA_ARGS__)
#define DEBUG(...)

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif
#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#define REGISTER_MAX_RANGE (1024 * 1024 * 1024)
#define REGISTER_MIN_RANGE -(1024 * 1024)
struct bpf_reg_state {
    enum ubpf_reg_type type;
    struct ubpf_map *map;
    struct {
        int64_t min;
        int64_t max;
    } s;
    struct {
        uint64_t min;
        uint64_t max;
    } u;
};

struct bpf_state {
    struct ovs_list node;
    struct bpf_reg_state regs[NB_REGS];
    struct bpf_reg_state stack[STACK_SIZE];
    uint32_t instno;
    uint64_t pkt_range;
};

enum vertex_status {
    UNDISCOVERED = 0,
    DISCOVERED,
    EXPLORED,
};

enum edge_status {
    UNLABELED = 0,
    BRANCH1_LABELED = 1,
    BRANCH2_LABELED = 2,
};

enum access_type {
    READ = 0,
    WRITE,
};

static bool validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts,
                     uint32_t num_insts, char **errmsg);
static bool validate_instructions(const struct ubpf_vm *vm,
                                  const struct ebpf_inst *insts,
                                  uint32_t num_insts, char **errmsg);
static bool validate_cfg(const struct ebpf_inst *insts, uint32_t num_insts,
                         char **errmsg);
static bool validate_accesses(const struct ubpf_vm *vm,
                                    const struct ebpf_inst *insts,
                                    char **errmsg);
static bool validate_reg_access(struct bpf_reg_state regs[], uint8_t regno,
                                uint32_t instno, enum access_type t,
                                char **errmsg);
static bool validate_mem_access(struct bpf_state *state, uint8_t regno,
                                struct ebpf_inst *inst, enum access_type t,
                                char **errmsg);
static bool validate_call(const struct ubpf_vm *vm, struct bpf_state *state,
                          int32_t func, char **errmsg);
static bool validate_jump(struct bpf_state *s, struct bpf_state *curr_state,
                          struct ebpf_inst *inst, char **errmsg);
static bool bounds_check(void *addr, int size, const char *type,
                         uint16_t cur_pc, void *mem, size_t mem_len,
                         void *stack);

static inline void
mark_bpf_reg_as_unknown(struct bpf_reg_state *reg) {
    reg->type = UNKNOWN;
    reg->u.max = UINT64_MAX;
    reg->u.min = 0;
    reg->s.max = INT64_MAX;
    reg->s.min = INT64_MIN;
    reg->map = NULL;
}

static inline void
mark_bpf_reg_as_imm(struct bpf_reg_state *reg, int32_t val) {
    reg->type = IMM;
    reg->s.min = val;
    reg->s.max = val;
    reg->u.min = val;
    reg->u.max = val;
    reg->map = NULL;
}

struct ubpf_vm *
ubpf_create(const ovs_be16 prog_id)
{
    struct ubpf_vm *vm = xcalloc(1, sizeof(*vm));
    vm->prog_id = prog_id;
    vm->ext_funcs = xcalloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    vm->ext_func_names = xcalloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    vm->ext_maps = xcalloc(MAX_EXT_MAPS, sizeof(*vm->ext_maps));
    vm->ext_map_names = xcalloc(MAX_EXT_MAPS, sizeof(*vm->ext_map_names));
    vm->nb_maps = 0;
    return vm;
}

void
ubpf_destroy(struct ubpf_vm *vm)
{
    if (vm->jitted) {
        munmap(vm->jitted, vm->jitted_size);
    }
    free(vm->insts);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm->ext_maps);
    free(vm->ext_map_names);
    free(vm);
}

int
ubpf_register_function(struct ubpf_vm *vm, unsigned int idx, const char *name,
                       struct ubpf_func_proto proto)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = proto;
    vm->ext_func_names[idx] = name;
    return 0;
}

int
ubpf_register_map(struct ubpf_vm *vm, const char *name, struct ubpf_map *map)
{
    unsigned int idx = vm->nb_maps;
    if (idx >= MAX_EXT_MAPS) {
        return -1;
    }
    vm->ext_maps[idx] = map;
    vm->ext_map_names[idx] = name;
    vm->nb_maps++;
    return 0;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char *other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

struct ubpf_map *
ubpf_lookup_registered_map(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_MAPS; i++) {
        const char *other = vm->ext_map_names[i];
        if (other && !strcmp(other, name)) {
            return vm->ext_maps[i];
        }
    }
    return NULL;
}

int
ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg)
{
    *errmsg = NULL;

    if (vm->insts) {
        *errmsg = ubpf_error("code has already been loaded into this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    #ifdef HAVE_BPF_VERIFIER
    /* FIXME: commented temporary */
    /* if (!validate(vm, code, code_len/8, errmsg)) {
        return -1;
    } */
    #endif

    vm->insts = xmalloc(code_len);

    memcpy(vm->insts, code, code_len);
    vm->num_insts = code_len/sizeof(vm->insts[0]);

    vm->loaded_at = (unsigned long long int) time_wall_msec();

    return 0;
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

uint64_t
ubpf_exec(const struct ubpf_vm *vm, void *mem, size_t mem_len)
{
    uint16_t pc = 0;
    const struct ebpf_inst *insts = vm->insts;
    uint64_t reg[16];
    uint64_t stack[(STACK_SIZE+7)/8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return UINT64_MAX;
    }

    reg[1] = (uintptr_t)mem;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;


        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] /= inst.imm;
            break;
        case EBPF_OP_DIV64_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] /= reg[inst.src];
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] %= inst.imm;
            break;
        case EBPF_OP_MOD64_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] %= reg[inst.src];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define BOUNDS_CHECK_LOAD(size) \
    do { \
        if (!bounds_check((void *)(reg[inst.src] + inst.offset), size, "load", cur_pc, mem, mem_len, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)
#define BOUNDS_CHECK_STORE(size) \
    do { \
        if (!bounds_check((void *)(reg[inst.dst] + inst.offset), size, "store", cur_pc, mem, mem_len, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            return reg[0];
        case EBPF_OP_CALL:
            reg[0] = vm->ext_funcs[inst.imm].func(reg[1], reg[2], reg[3], reg[4], reg[5]);
            break;
        }
    }
}

__attribute__((unused)) static bool
validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts,
         uint32_t num_insts, char **errmsg) {
    if (num_insts >= MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
        return false;
    }

    if (!validate_instructions(vm, insts, num_insts, errmsg))
        return false;

    if (!validate_cfg(insts, num_insts, errmsg))
        return false;

    if (!validate_accesses(vm, insts, errmsg))
        return false;

    return true;
}

static bool
validate_reg_access(struct bpf_reg_state regs[], uint8_t regno, uint32_t instno,
                    enum access_type t, char **errmsg) {
    if (regno >= NB_REGS) {
        *errmsg = ubpf_error("invalid register %d at PC %d", regno, instno);
        return false;
    }
    if (t == READ && regs[regno].type == UNINIT) {
        *errmsg = ubpf_error("uninitialized register %d at PC %d", regno,
                             instno);
        return false;
    }
    if (regno == 10 && t == WRITE) {
        *errmsg = ubpf_error("R10 is read only");
        return false;
    }
    return true;
}

static bool
is_pointer_type(enum ubpf_reg_type type) {
    return type & (MAP_PTR | MAP_VALUE_PTR | PKT_PTR | STACK_PTR | CTX_PTR);
}

static void
invalidate_pkt_pointers(struct bpf_state *state) {
    unsigned int i;

    for (i = 0; i < NB_REGS; i++)
        if (state->regs[i].type == PKT_PTR)
            mark_bpf_reg_as_unknown(&state->regs[i]);

    for (i = 0; i < STACK_SIZE; i++)
        if (state->stack[i].type == PKT_PTR)
            mark_bpf_reg_as_unknown(&state->stack[i]);

    DEBUG("\tInvalidated packet pointers\n");
}

static bool
validate_call(const struct ubpf_vm *vm, struct bpf_state *state,
              int32_t func, char **errmsg) {
    enum ubpf_reg_type expected_type;
    enum ubpf_arg_size expected_size;
    struct ubpf_func_proto proto = vm->ext_funcs[func];
    int i, j;
    int64_t min_val;
    uint64_t max_val;
    struct bpf_reg_state *reg, *next_reg;
    struct ubpf_map *map, *arg_map;

    for (i = 1; i <= NB_FUNC_ARGS; i++) {
        reg = &state->regs[i];
        expected_type = proto.arg_types[i - 1];
        if (expected_type != MAP_PTR &&
            (expected_type & reg->type) != reg->type) {
            *errmsg = ubpf_error("incorrect argument type for func %d arg %d "
                                 "at PC %d (expected %d, got %d)",
                                 func, i, state->instno, expected_type,
                                 reg->type);
            return false;
        }

        expected_size = proto.arg_sizes[i - 1];
        if (expected_size == 0xff) {
            // We can skip argument size verifications.
            continue;
        }

        if (is_pointer_type(reg->type)) {
            if (expected_size == SIZE_64) {
                *errmsg = ubpf_error("incorrect argument size for func %d arg "
                                     "%d at PC %d (expected value, got "
                                     "pointer)", func, i, state->instno);
                return false;
            }

            unsigned int size;
            if (expected_size == SIZE_PTR_MAX) {
                // Next argument should be constant imm, < MAX_SIZE_ARG:
                next_reg = &state->regs[i + 1];
                if (next_reg->type == IMM && next_reg->u.max > MAX_SIZE_ARG
                    && next_reg->u.min == next_reg->u.max) {
                    *errmsg = ubpf_error("incorrect argument for func %d arg "
                                         "%d at PC %d", func, i + 1,
                                         state->instno);
                    return false;
                }
                size = next_reg->u.min;
            } else {
                map = state->regs[1].map;
                if (!map) {
                    *errmsg = ubpf_error("R1 should point to map at PC %d",
                                         state->instno);
                    return false;
                }
                size = (expected_size == SIZE_MAP_KEY)?
                            map->key_size : map->value_size;
            }

            min_val = reg->s.min;
            max_val = reg->u.max;
            switch (reg->type) {
                case PKT_PTR:
                    if (min_val < 0 || size + max_val > state->pkt_range) {
                        *errmsg = ubpf_error("invalid access to packet (%d +"
                                             " %d > %d) at PC %d", max_val,
                                             size, state->pkt_range,
                                             state->instno);
                        return false;
                    }
                    break;

                case CTX_PTR:
                    if (min_val || max_val) {
                        *errmsg = ubpf_error("invalid access to ctx at PC"
                                             " %d", state->instno);
                        return false;
                    }
                    break;

                case STACK_PTR:
                    if (min_val != max_val) {
                        *errmsg = ubpf_error("variable access to stack at PC %d"
                                             ", arg %d", state->instno, i);
                        return false;
                    }
                    if (min_val < -STACK_SIZE || min_val + size > 0) {
                        *errmsg = ubpf_error("invalid access to stack at PC %d"
                                             ", arg %d", state->instno, i);
                        return false;
                    }
                    for (j = STACK_SIZE + min_val;
                         j < STACK_SIZE + min_val + size; j++) {
                        if (state->stack[j].type == UNINIT) {
                            *errmsg = ubpf_error("reading uninitialized stack "
                                                 "byte %d at PC %d", j,
                                                 state->instno);
                            return false;
                        }
                    }
                    break;

                case MAP_VALUE_PTR:
                    if (max_val == REGISTER_MAX_RANGE) {
                        *errmsg = ubpf_error("unbounded access to map value at"
                                             " PC %d", state->instno);
                        return false;
                    }
                    arg_map = state->regs[i].map;
                    if (!arg_map) {
                        *errmsg = ubpf_error("R%d should point to map at PC "
                                             "%d", i, state->instno);
                        return false;
                    }
                    if (min_val < 0 || size + max_val > arg_map->value_size) {
                        *errmsg = ubpf_error("invalid access to map value at "
                                             "PC %d", state->instno);
                        return false;
                    }
                    break;

                case UNINIT:
                case UNKNOWN:
                case NULL_VALUE:
                case IMM:
                case MAP_PTR:
                case PKT_SIZE:
                    *errmsg = ubpf_error("invalid memory access at PC %d",
                                         state->instno);
                    return false;
            }

        } else {
            if (proto.arg_sizes[i - 1] != SIZE_64) {
                *errmsg = ubpf_error("incorrect argument size for func %d arg "
                                     "%d at PC %d (expected pointer, got"
                                     " value)", func, i, state->instno);
                return false;
            }
        }
    }

    if (func == UBPF_ADJUST_HEAD_ID) {
        invalidate_pkt_pointers(state);
        state->pkt_range += state->regs[2].s.min;
        DEBUG("\tKnown pkt range has been updated to %lu (+ %d)\n",
              state->pkt_range, state->regs[2].s.min);
    }

    if (proto.ret == (MAP_VALUE_PTR | NULL_VALUE)
        && proto.arg_types[0] == MAP_PTR) {
        state->regs[0].type = proto.ret;
        state->regs[0].map = state->regs[1].map;
        // Offsets from the start of map value:
        state->regs[0].u.min = 0;
        state->regs[0].u.max = 0;
        state->regs[0].s.min = 0;
        state->regs[0].s.max = 0;
        DEBUG("\tAssigned map %p to R0\n", state->regs[1].map);
    } else if (proto.ret == PKT_PTR) {
        state->regs[0].type = proto.ret;
        state->regs[0].map = NULL;
        // Offsets from the start of pkt:
        state->regs[0].u.min = 0;
        state->regs[0].u.max = 0;
        state->regs[0].s.min = 0;
        state->regs[0].s.max = 0;
        DEBUG("\tAssigned pkt_ptr to R0\n");
    } else {
        mark_bpf_reg_as_unknown(&state->regs[0]);
        DEBUG("\tR0 marked as unknown\n");
    }
    DEBUG("\tR0 now has type 0x%x\n", proto.ret);

    return true;
}

static void
handle_min_max_overflows(struct bpf_reg_state *reg, uint64_t mask) {
    if (((reg->u.min & mask) != reg->u.min) || ((reg->u.max & mask) != reg->u.max)) {
        reg->u.max = MAX(mask, reg->u.max);
        reg->u.min = 0;
    }

    reg->s.max = MIN(mask >> 1, reg->s.max);
    reg->s.min = MAX((int64_t)((mask >> 1) ^ UINT64_MAX), reg->s.min);
}

static void
update_min_max_jump_imm(struct bpf_reg_state *true_reg,
                        uint64_t *true_pkt_range,
                        struct bpf_reg_state *false_reg,
                        uint64_t *false_pkt_range, uint8_t opcode,
                        uint64_t val) {
    switch (opcode) {
        case EBPF_JMP_JEQ:
            true_reg->s.min = val;
            true_reg->s.max = val;
            true_reg->u.min = val;
            true_reg->u.max = val;
            break;
        case EBPF_JMP_JGT:
            // reg > val if true, reg <= val if false.
            true_reg->u.min = val + 1;
            false_reg->u.max = val;
            break;
        case EBPF_JMP_JGE:
            // reg >= val if true, reg < val if false.
            true_reg->u.min = val;
            false_reg->u.max = val - 1;
            break;
        case EBPF_JMP_JNE:
            false_reg->s.min = val;
            false_reg->s.max = val;
            false_reg->u.min = val;
            false_reg->u.max = val;
            break;
        case EBPF_JMP_JSGT:
            // reg > val if true, reg <= val if false.
            true_reg->s.min = val + 1;
            false_reg->s.max = val;
            break;
        case EBPF_JMP_JSGE:
            // reg >= val if true, reg < val if false.
            true_reg->s.min = val;
            false_reg->s.max = val - 1;
            break;
    }

    // Update pkt_range to remember it independantly of registers' lifes.
    if (true_reg->type == PKT_SIZE && true_reg->u.min > *true_pkt_range) {
        *true_pkt_range = true_reg->u.min;
    }
    if (false_reg->type == PKT_SIZE && false_reg->u.min > *false_pkt_range) {
        *false_pkt_range = false_reg->u.min;
    }
}

static void
update_min_max_jump_imm_inv(struct bpf_reg_state *true_reg,
                            uint64_t *true_pkt_range,
                            struct bpf_reg_state *false_reg,
                            uint64_t *false_pkt_range, uint8_t opcode,
                            uint64_t val) {
    switch (opcode) {
        case EBPF_JMP_JEQ:
            true_reg->s.min = val;
            true_reg->s.max = val;
            true_reg->u.min = val;
            true_reg->u.max = val;
            break;
        case EBPF_JMP_JGT:
            // val > reg if true, val <= reg if false.
            true_reg->u.max = val - 1;
            false_reg->u.min = val;
            break;
        case EBPF_JMP_JGE:
            // val >= reg if true, val < reg if false.
            true_reg->u.max = val;
            false_reg->u.min = val + 1;
            break;
        case EBPF_JMP_JNE:
            false_reg->s.min = val;
            false_reg->s.max = val;
            false_reg->u.min = val;
            false_reg->u.max = val;
            break;
        case EBPF_JMP_JSGT:
            // val > reg if true, val <= reg if false.
            true_reg->s.max = val - 1;
            false_reg->s.min = val;
            break;
        case EBPF_JMP_JSGE:
            // val >= reg if true, val < reg if false.
            true_reg->s.max = val;
            false_reg->s.min = val + 1;
            break;
    }

    // Update pkt_range to remember it independantly of registers' lifes.
    if (true_reg->type == PKT_SIZE && true_reg->u.min > *true_pkt_range) {
        *true_pkt_range = true_reg->u.min;
    }
    if (false_reg->type == PKT_SIZE && false_reg->u.min > *false_pkt_range) {
        *false_pkt_range = false_reg->u.min;
    }
}

static int
update_min_max_jump_reg(struct bpf_reg_state *true_reg1,
                        struct bpf_reg_state *true_reg2,
                        uint64_t *true_pkt_range,
                        struct bpf_reg_state *false_reg1,
                        struct bpf_reg_state *false_reg2,
                        uint64_t *false_pkt_range, uint8_t opcode) {
    // reg1 \in [a;b], reg2 \in [c;d]
    int64_t sa, sb, sc, sd;
    uint64_t ua, ub, uc, ud;
    bool signed_intersect, unsigned_intersect;

    switch (opcode) {
        case EBPF_JMP_JEQ:
            sa = true_reg1->s.min, sc = true_reg2->s.min;
            sb = true_reg1->s.max, sd = true_reg2->s.max;
            ua = true_reg1->u.min, uc = true_reg2->u.min;
            ub = true_reg1->u.max, ud = true_reg2->u.max;
            signed_intersect = (sc <= sa && sa <= sd) ||
                               (sc <= sb && sb <= sd) ||
                               (sa <= sc && sc <= sb);
            unsigned_intersect = (uc <= ua && ua <= ud) ||
                                 (uc <= ub && ub <= ud) ||
                                 (ua <= uc && uc <= ub);
            // Check that they intersect.
            if (!signed_intersect || !unsigned_intersect) {
                return -1;
            }
            // If egal, their range is the intersection.
            true_reg1->s.min = MAX(sa, sc);
            true_reg1->s.max = MIN(sb, sd);
            true_reg2->s = true_reg1->s;
            break;

        case EBPF_JMP_JGT:
            // reg1 > reg2 is true.
            true_reg1->u.min = MAX(true_reg1->u.min, true_reg2->u.min + 1);
            true_reg2->u.max = MIN(true_reg1->u.max - 1, true_reg2->u.max);
            // reg1 <= reg2 is true.
            false_reg1->u.max = MIN(false_reg1->u.max, false_reg2->u.max);
            false_reg2->u.min = MAX(false_reg1->u.min, false_reg2->u.min);
            break;

        case EBPF_JMP_JGE:
            // reg1 >= reg2 is true.
            true_reg1->u.min = MAX(true_reg1->u.min, true_reg2->u.min);
            true_reg2->u.max = MIN(true_reg1->u.max, true_reg2->u.max);
            // reg1 <= reg2 is true.
            false_reg1->u.max = MIN(false_reg1->u.max, false_reg2->u.max - 1);
            false_reg2->u.min = MAX(false_reg1->u.min + 1, false_reg2->u.min);
            break;

        case EBPF_JMP_JNE:
            sa = false_reg1->s.min, sc = false_reg2->s.min;
            sb = false_reg1->s.max, sd = false_reg2->s.max;
            ua = false_reg1->u.min, uc = false_reg2->u.min;
            ub = false_reg1->u.max, ud = false_reg2->u.max;
            signed_intersect = (sc <= sa && sa <= sd) ||
                               (sc <= sb && sb <= sd) ||
                               (sa <= sc && sc <= sb);
            unsigned_intersect = (uc <= ua && ua <= ud) ||
                                 (uc <= ub && ub <= ud) ||
                                 (ua <= uc && uc <= ub);
            // Check that they intersect.
            if (!signed_intersect || !unsigned_intersect) {
                return -1;
            }
            // If egal, their range is the intersection.
            false_reg1->s.min = MAX(sa, sc);
            false_reg1->s.max = MIN(sb, sd);
            false_reg2->s = false_reg1->s;
            break;

        case EBPF_JMP_JSGT:
            // reg1 > reg2 is true.
            true_reg1->s.min = MAX(true_reg1->s.min, true_reg2->s.min + 1);
            true_reg2->s.max = MIN(true_reg1->s.max - 1, true_reg2->s.max);
            // reg1 <= reg2 is true.
            false_reg1->s.max = MIN(false_reg1->s.max, false_reg2->s.max);
            false_reg2->s.min = MAX(false_reg1->s.min, false_reg2->s.min);
            break;

        case EBPF_JMP_JSGE:
            // reg1 >= reg2 is true.
            true_reg1->s.min = MAX(true_reg1->s.min, true_reg2->s.min);
            true_reg2->s.max = MIN(true_reg1->s.max, true_reg2->s.max);
            // reg1 <= reg2 is true.
            false_reg1->s.max = MIN(false_reg1->s.max, false_reg2->s.max - 1);
            false_reg2->s.min = MAX(false_reg1->s.min + 1, false_reg2->s.min);
            return 0;
    }

    // Update pkt_range to remember it independantly of registers' lifes.
    if (true_reg1->type == PKT_SIZE && true_reg1->u.min > *true_pkt_range) {
        *true_pkt_range = true_reg1->u.min;
    }
    if (true_reg2->type == PKT_SIZE && true_reg2->u.min > *true_pkt_range) {
        *true_pkt_range = true_reg2->u.min;
    }
    if (false_reg1->type == PKT_SIZE && false_reg1->u.min > *false_pkt_range) {
        *false_pkt_range = false_reg1->u.min;
    }
    if (false_reg2->type == PKT_SIZE && false_reg2->u.min > *false_pkt_range) {
        *false_pkt_range = false_reg2->u.min;
    }

    return 0;
}

static bool
validate_jump(struct bpf_state *s, struct bpf_state *curr_state,
              struct ebpf_inst *inst, char **errmsg) {
    struct bpf_reg_state *dst_reg, *src_reg;

    if (!validate_reg_access(curr_state->regs, inst->dst, curr_state->instno,
                             READ, errmsg))
        return false;
    if (EBPF_SRC(inst->opcode) == EBPF_SRC_REG) {
        if (!validate_reg_access(curr_state->regs, inst->src,
                                 curr_state->instno, READ, errmsg))
            return false;
    }

    // Push bpf_state for other branch to stack:
    struct bpf_state *other_branch = calloc(1, sizeof(struct bpf_state));
    memcpy(other_branch, curr_state, sizeof(struct bpf_state));
    ovs_list_push_front(&s->node, &other_branch->node);
    other_branch->instno += inst->offset + 1;

    dst_reg = &curr_state->regs[inst->dst];
    src_reg = &curr_state->regs[inst->src];

    if (EBPF_SRC(inst->opcode) == EBPF_SRC_REG) {
        if (dst_reg->type == IMM) {
            // If type == IMM, then min == max.
            update_min_max_jump_imm_inv(&other_branch->regs[inst->src],
                                        &other_branch->pkt_range,
                                        src_reg,
                                        &curr_state->pkt_range,
                                        EBPF_OP(inst->opcode),
                                        dst_reg->u.min);
            DEBUG("\tR%d (t=%d) may have updated range [%ld;%ld] U [%lu;%lu]\n",
                  inst->src, src_reg->type, src_reg->s.min, src_reg->s.max,
                  src_reg->u.min, src_reg->u.max);
        } else if (src_reg->type == IMM) {
            // If type == IMM, then min == max.
            update_min_max_jump_imm(&other_branch->regs[inst->dst],
                                    &other_branch->pkt_range, dst_reg,
                                    &curr_state->pkt_range,
                                    EBPF_OP(inst->opcode), src_reg->u.min);
            DEBUG("\tR%d (t=%d) may have updated range [%ld;%ld] U [%lu;%lu]\n",
                  inst->dst, dst_reg->type, dst_reg->s.min, dst_reg->s.max,
                  dst_reg->u.min, dst_reg->u.max);
        } else if ((dst_reg->type == UNKNOWN || dst_reg->type == PKT_SIZE) &&
                   (src_reg->type == UNKNOWN || src_reg->type == PKT_SIZE)) {
            update_min_max_jump_reg(&other_branch->regs[inst->dst],
                                    &other_branch->regs[inst->src],
                                    &other_branch->pkt_range,
                                    dst_reg, src_reg, &curr_state->pkt_range,
                                    EBPF_OP(inst->opcode));
            DEBUG("\tR%d (t=%d) may have updated range [%ld;%ld] U [%lu;%lu]\n",
                  inst->dst, dst_reg->type, dst_reg->s.min, dst_reg->s.max,
                  dst_reg->u.min, dst_reg->u.max);
            DEBUG("\tR%d (t=%d) may have updated range [%ld;%ld] U [%lu;%lu]\n",
                  inst->src, src_reg->type, src_reg->s.min, src_reg->s.max,
                  src_reg->u.min, src_reg->u.max);
        }
    } else {
        update_min_max_jump_imm(&other_branch->regs[inst->dst],
                                &other_branch->pkt_range, dst_reg,
                                &curr_state->pkt_range,
                                EBPF_OP(inst->opcode), inst->imm);
        DEBUG("\tR%d (t=%d) may have updated range [%ld;%ld] U [%lu;%lu]\n",
              inst->dst, dst_reg->type, dst_reg->s.min, dst_reg->s.max,
              dst_reg->u.min, dst_reg->u.max);
    }

    if (dst_reg->type == (MAP_VALUE_PTR | NULL_VALUE)
        && (inst->opcode == EBPF_OP_JEQ_IMM || inst->opcode == EBPF_OP_JNE_IMM)
        && inst->imm == 0) {
        uint8_t opcode = EBPF_OP(inst->opcode);
        curr_state->regs[inst->dst].type =
            (opcode == EBPF_JMP_JEQ)? MAP_VALUE_PTR : NULL_VALUE;
        other_branch->regs[inst->dst].type =
            (opcode == EBPF_JMP_JEQ)? NULL_VALUE : MAP_VALUE_PTR;
    }

    return true;
}

static inline uint64_t
compute_bitwise_and_bound(uint64_t a, uint64_t b, unsigned int opsize) {
    a = __builtin_clzll(a);
    b = __builtin_clzll(b);
    return -1ULL >> (64 - (opsize - MAX(a, b)));
}

static inline uint64_t
compute_bitwise_or_bound(uint64_t a, uint64_t b, unsigned int opsize) {
    a = __builtin_clzll(a);
    b = __builtin_clzll(b);
    return -1ULL >> (64 - (opsize - MIN(a, b)));
}

static void
update_min_max_alu_op(struct bpf_reg_state regs[], struct ebpf_inst *inst) {
    struct bpf_reg_state *dst_reg = &regs[inst->dst];
    struct bpf_reg_state src_reg;
    uint64_t mask = (EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64)? 0xffffffffffffffff : 0xffffffff;
    unsigned int opsize = (EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64)? 64 : 32;

    if (EBPF_SRC(inst->opcode) == EBPF_SRC_REG) {
        src_reg = regs[inst->src];
        handle_min_max_overflows(&src_reg, mask);
    } else {
        mark_bpf_reg_as_imm(&src_reg, inst->imm);
    }
    handle_min_max_overflows(dst_reg, mask);

    struct bpf_reg_state nr;
    nr.u.min = 0;
    nr.u.max = 0;
    switch(EBPF_OP(inst->opcode)) {
        case EBPF_ALU_ADD:
            nr.u.min = (dst_reg->u.min + src_reg.u.min) & mask;
            nr.u.max = (dst_reg->u.max + src_reg.u.max) & mask;
            nr.s.min = (dst_reg->s.min + src_reg.s.min) & mask;
            nr.s.max = (dst_reg->s.max + src_reg.s.max) & mask;

            // Check for overflows:
            if ((nr.u.min < dst_reg->u.min || nr.u.max < dst_reg->u.max) &&
                (dst_reg->u.min != dst_reg->u.max || src_reg.u.min != src_reg.u.max)) {
                nr.u.max = MAX(mask, nr.u.max);
                nr.u.min = 0;
            }
            if ((((src_reg.s.min < 0 && nr.s.min > dst_reg->s.min) || nr.s.min < dst_reg->s.min) ||
                 ((src_reg.s.max < 0 && nr.s.max > dst_reg->s.max) || nr.s.max < dst_reg->s.max)) &&
                (dst_reg->s.min != dst_reg->s.max || src_reg.s.min != src_reg.s.max)) {
                nr.s.max = mask >> 1;
                nr.s.min = (mask >> 1) ^ UINT64_MAX;
            }

            dst_reg->u = nr.u;
            dst_reg->s = nr.s;
            break;

        case EBPF_ALU_SUB:
            nr.u.min = (dst_reg->u.min - src_reg.u.min) & mask;
            nr.u.max = (dst_reg->u.max - src_reg.u.max) & mask;
            nr.s.min = (dst_reg->s.min - src_reg.s.min) & mask;
            nr.s.max = (dst_reg->s.max - src_reg.s.max) & mask;

            // Check for overflows:
            if ((nr.u.min > dst_reg->u.min || nr.u.max > dst_reg->u.max) &&
                (dst_reg->u.min != dst_reg->u.max || src_reg.u.min != src_reg.u.max)) {
                nr.u.max = MAX(mask, nr.u.max);
                nr.u.min = 0;
            }
            if ((((src_reg.s.min < 0 && nr.s.min < dst_reg->s.min) || nr.s.min > dst_reg->s.min) ||
                 ((src_reg.s.max < 0 && nr.s.max < dst_reg->s.max) || nr.s.max > dst_reg->s.max)) &&
                (dst_reg->s.min != dst_reg->s.max || src_reg.s.min != src_reg.s.max)) {
                nr.s.max = mask >> 1;
                nr.s.min = (mask >> 1) ^ UINT64_MAX;
            }

            dst_reg->u = nr.u;
            dst_reg->s = nr.s;
            break;

        case EBPF_ALU_MUL:

            if (dst_reg->u.min == dst_reg->u.max && src_reg.u.min == src_reg.u.max) {
                dst_reg->u.min = (dst_reg->u.min * src_reg.u.min) & mask;
                dst_reg->u.max = (dst_reg->u.max * src_reg.u.max) & mask;
            } else if (dst_reg->u.max <= mask >> opsize / 2 && src_reg.u.max <= mask >> opsize) {
                // We've checked for overflows already (same boundaries as DPDK).
                dst_reg->u.max *= src_reg.u.max;
                dst_reg->u.min *= dst_reg->u.min;
            } else {
                dst_reg->u.max = MAX(mask, nr.u.max);
                dst_reg->u.min = 0;
            }

            if (dst_reg->s.min == dst_reg->s.max && src_reg.s.min == src_reg.s.max) {
                dst_reg->s.min = (dst_reg->s.min * src_reg.s.min) & mask;
                dst_reg->s.max = (dst_reg->s.max * src_reg.s.max) & mask;
            } else if (dst_reg->s.min >= 0 && src_reg.s.min >= 0) {
                // Both are positives so no overflows.
                dst_reg->s.max *= src_reg.s.max;
                dst_reg->s.min *= dst_reg->s.min;
            } else {
                dst_reg->s.max = mask >> 1;
                dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
            }
            break;

        case EBPF_ALU_AND:
            if (dst_reg->u.min == dst_reg->u.max && src_reg.u.min == src_reg.u.max) {
                dst_reg->u.min &= src_reg.u.min;
                dst_reg->u.max &= src_reg.u.max;
            } else {
                dst_reg->u.max = compute_bitwise_and_bound(dst_reg->u.max,
                                                           src_reg.u.max, opsize);
                dst_reg->u.min &= src_reg.u.min;
            }

            if (dst_reg->s.min == dst_reg->s.max && src_reg.s.min == src_reg.s.max) {
                dst_reg->s.min &= src_reg.s.min;
                dst_reg->s.max &= src_reg.s.max;
            } else if (dst_reg->s.min >= 0 || src_reg.s.min >= 0) {
                dst_reg->s.max = compute_bitwise_and_bound(dst_reg->s.max & (mask >> 1),
                                                           src_reg.s.max & (mask >> 1),
                                                           opsize);
                dst_reg->s.min &= src_reg.s.min;
            } else {
                dst_reg->s.max = mask >> 1;
                dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
            }
            break;

        case EBPF_ALU_OR:
            if (dst_reg->u.min == dst_reg->u.max && src_reg.u.min == src_reg.u.max) {
                dst_reg->u.min |= src_reg.u.min;
                dst_reg->u.max |= src_reg.u.max;
            } else {
                dst_reg->u.max = compute_bitwise_or_bound(dst_reg->u.max,
                                                           src_reg.u.max, opsize);
                dst_reg->u.min |= src_reg.u.min;
            }

            if (dst_reg->s.min == dst_reg->s.max && src_reg.s.min == src_reg.s.max) {
                dst_reg->s.min |= src_reg.s.min;
                dst_reg->s.max |= src_reg.s.max;
            } else if (dst_reg->s.min >= 0 || src_reg.s.min >= 0) {
                dst_reg->s.max = compute_bitwise_or_bound(dst_reg->s.max & (mask >> 1),
                                                           src_reg.s.max & (mask >> 1),
                                                           opsize);
                dst_reg->s.min |= src_reg.s.min;
            } else {
                dst_reg->s.max = mask >> 1;
                dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
            }
            break;

        case EBPF_ALU_LSH:
            if (src_reg.u.max >= opsize) {
                dst_reg->u.max = MAX(mask, nr.u.max);
                dst_reg->u.min = 0;
                dst_reg->s.max = mask >> 1;
                dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
            } else {
                if (dst_reg->u.max <= -1ULL >> (64 - (opsize - src_reg.u.max))) {
                    dst_reg->u.min <<= src_reg.u.min;
                    dst_reg->u.max <<= src_reg.u.max;
                } else {
                    dst_reg->u.max = MAX(mask, nr.u.max);
                    dst_reg->u.min = 0;
                }

                if (dst_reg->s.min >> (opsize - 1) == 0 &&
                    dst_reg->s.max < ((int64_t)(-1ULL >> (64 - (opsize - src_reg.u.max - 1))))) {
                    // bounds will remain positives so no overflows.
                    dst_reg->s.min <<= src_reg.u.min;
                    dst_reg->s.max <<= src_reg.u.max;
                } else {
                    dst_reg->s.max = mask >> 1;
                    dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
                }
            }
            break;

        case EBPF_ALU_RSH:
            if (src_reg.u.max >= opsize) {
                dst_reg->u.max = MAX(mask, nr.u.max);
                dst_reg->u.min = 0;
                dst_reg->s.max = mask >> 1;
                dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
            } else {
                dst_reg->u.min >>= src_reg.u.min;
                dst_reg->u.max >>= src_reg.u.max;

                if ((uint64_t)dst_reg->s.min >> (opsize - 1) == 0) {
                    dst_reg->s.min >>= src_reg.u.min;
                    dst_reg->s.max >>= src_reg.u.max;
                } else {
                    dst_reg->s.max = mask >> 1;
                    dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
                }
            }
            break;

        default:
            dst_reg->u.max = MAX(mask, nr.u.max);
            dst_reg->u.min = 0;
            dst_reg->s.max = mask >> 1;
            dst_reg->s.min = (mask >> 1) ^ UINT64_MAX;
    }

    DEBUG("\tR%d (t=%d) has updated range [%ld;%ld] U [%lu;%lu]\n", inst->dst, dst_reg->type, dst_reg->s.min, dst_reg->s.max, dst_reg->u.min, dst_reg->u.max);
}

static bool
validate_alu_op(struct bpf_state *state, struct ebpf_inst *inst,
                char **errmsg) {
    validate_reg_access(state->regs, inst->src, state->instno, READ, errmsg);
    validate_reg_access(state->regs, inst->dst, state->instno, WRITE, errmsg);

    struct bpf_reg_state *dst_reg = &state->regs[inst->dst];
    switch(EBPF_OP(inst->opcode)) {
        case EBPF_ALU_END:
        case EBPF_ALU_NEG:
            break;

        case EBPF_ALU_MOV:
            if (EBPF_SRC(inst->opcode) == EBPF_SRC_REG) {
                if (EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64) {
                    *dst_reg = state->regs[inst->src];
                } else {
                    mark_bpf_reg_as_unknown(dst_reg);
                }
            } else {
                mark_bpf_reg_as_imm(dst_reg, inst->imm);
            }
            DEBUG("\tR%d now has type 0x%x, range [%ld;%ld] U [%lu;%lu]\n",
                  inst->dst, dst_reg->type, dst_reg->s.min, dst_reg->s.max,
                  dst_reg->u.min, dst_reg->u.max);
            break;

        default: {
            uint8_t op = EBPF_OP(inst->opcode);
            if ((op == EBPF_ALU_SUB || op == EBPF_ALU_ADD)
                && dst_reg->type == STACK_PTR
                && EBPF_SRC(inst->opcode) == EBPF_SRC_IMM
                && EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64) {
                // STACK_PTR arithmetic.
            } else if ((op == EBPF_ALU_SUB || op == EBPF_ALU_ADD)
                       && dst_reg->type == PKT_PTR
                       && EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64) {
                // PKT_PTR arithmetic.
            } else if ((op == EBPF_ALU_SUB || op == EBPF_ALU_ADD)
                       && dst_reg->type == MAP_VALUE_PTR
                       && EBPF_SRC(inst->opcode) == EBPF_SRC_IMM
                       && EBPF_CLASS(inst->opcode) == EBPF_CLS_ALU64) {
                // MAP_VALUE_PTR arithmetic.
            } else if (is_pointer_type(dst_reg->type)
                       || (EBPF_SRC(inst->opcode) == EBPF_SRC_REG
                           && is_pointer_type(state->regs[inst->src].type))) {
                *errmsg = ubpf_error("forbidden pointer arithmetic at PC %d",
                                     state->instno);
                return false;
            }

            update_min_max_alu_op(state->regs, inst);
        }
    }

    return true;
}

static int
size_in_bytes(uint8_t opcode) {
    switch(EBPF_SIZE(opcode)) {
        case EBPF_SIZE_B:
            return 1;
        case EBPF_SIZE_H:
            return 2;
        case EBPF_SIZE_W:
            return 4;
        case EBPF_SIZE_DW:
            return 8;
    }
    return -1;
}

static bool
validate_mem_access(struct bpf_state *state, uint8_t regno,
                    struct ebpf_inst *inst, enum access_type t, char **errmsg) {
    struct ubpf_map *map;
    int64_t min_val;
    uint64_t max_val;

    int size = size_in_bytes(inst->opcode);

    switch (state->regs[regno].type) {
        case PKT_PTR:
            min_val = state->regs[regno].s.min;
            max_val = state->regs[regno].u.max;

            DEBUG("\t%d + %lu + %d < %lu\n", inst->offset, max_val, size, state->pkt_range);
            if (inst->offset + min_val < 0
                || inst->offset + max_val + size > state->pkt_range) {
                *errmsg = ubpf_error("invalid access to packet (%d + %d > %d)"
                                     " at PC %d", inst->offset + max_val, size,
                                     state->pkt_range, state->instno);
                return false;
            }
            break;

        case STACK_PTR:
            if (inst->offset >= 0 || inst->offset < -STACK_SIZE) {
                *errmsg = ubpf_error("invalid stack access at PC %d",
                                     state->instno);
                return false;
            }
            if (t == WRITE) {
                for (int i = STACK_SIZE + inst->offset;
                     i < STACK_SIZE + inst->offset + size; i++) {
                    state->stack[i].type = UNKNOWN;
                }
                // Look for spilled register invalidated by this stack write.
                for (int i = STACK_SIZE + inst->offset - 1; i < STACK_SIZE + inst->offset - 8; i--) {
                    if (state->stack[i].type != UNINIT && state->stack[i].type != UNKNOWN) {
                        state->stack[i].type = UNKNOWN;
                        break;
                    }
                }
            } else {
                for (int i = STACK_SIZE + inst->offset;
                     i < STACK_SIZE + inst->offset + size; i++) {
                    if (state->stack[i].type == UNINIT) {
                        *errmsg = ubpf_error("reading uninitialized stack byte"
                                             " at PC %d", state->instno);
                        return false;
                    }
                }
            }
            break;

        case MAP_VALUE_PTR:
            min_val = state->regs[regno].s.min;
            max_val = state->regs[regno].u.max;
            if (max_val == REGISTER_MAX_RANGE) {
                *errmsg = ubpf_error("unbounded access to map value at PC %d",
                                     state->instno);
                return false;
            }
            map = state->regs[regno].map;
            if (!map) {
                *errmsg = ubpf_error("fatal error: R%d should point to map at "
                                     "PC %d", regno, state->instno);
                return false;
            }
            if (inst->offset + min_val < 0 ||
                inst->offset + size + max_val > map->value_size) {
                *errmsg = ubpf_error("invalid access to map value at PC %d",
                                     state->instno);
                return false;
            }
            break;

        case UNINIT:
        case UNKNOWN:
        case NULL_VALUE:
        case IMM:
        case MAP_PTR:
        case PKT_SIZE:
        case CTX_PTR:
            *errmsg = ubpf_error("invalid memory access at PC %d", state->instno);
            return false;
    }
    return true;
}

static bool
validate_accesses(const struct ubpf_vm *vm,
                        const struct ebpf_inst *insts,
                        char **errmsg) {
    struct bpf_state *s = calloc(1, sizeof(struct bpf_state));
    ovs_list_init(&s->node);
    s->regs[1].type = CTX_PTR;
    s->regs[2].type = PKT_SIZE;
    s->regs[2].u.max = UINT64_MAX;
    s->regs[2].u.min = 0;
    s->regs[2].s.max = INT64_MAX;
    s->regs[2].s.min = INT64_MIN;
    s->regs[10].type = STACK_PTR;
    struct bpf_state *curr_state = s;
    while (true) {
        struct ebpf_inst inst = insts[curr_state->instno];
        uint8_t class = EBPF_CLASS(inst.opcode);
        DEBUG("PC=%u, class=0x%x, opcode=0x%x\n", curr_state->instno, class, inst.opcode);
        switch (class) {
            case EBPF_CLS_JMP:
                switch (inst.opcode) {
                    case EBPF_OP_JA:
                        DEBUG("\tunconditional jump from PC %d to PC %d\n", curr_state->instno, curr_state->instno + inst.offset + 1);
                        curr_state->instno += inst.offset + 1;
                        continue;

                    case EBPF_OP_CALL:
                        if (!validate_call(vm, curr_state, inst.imm, errmsg))
                            return false;
                        break;

                    case EBPF_OP_EXIT:
                        if (!validate_reg_access(curr_state->regs, 0,
                                                 curr_state->instno, READ,
                                                 errmsg))
                            return false;
                        if (ovs_list_is_empty(&s->node)) {
                            DEBUG("No more states to explore!\n\n");
                            return true;
                        }
                        curr_state = CONTAINER_OF(ovs_list_pop_front(&s->node),
                                                  struct bpf_state, node);
                        DEBUG("\nPopped state with PC=%d\n", curr_state->instno);
                        continue;

                    default:
                        if (!validate_jump(s, curr_state, &inst, errmsg))
                            return false;
                }
                break;

            case EBPF_CLS_ST:
            case EBPF_CLS_STX:
                if (!validate_reg_access(curr_state->regs, inst.dst,
                                         curr_state->instno, READ, errmsg))
                    return false;
                if (!validate_reg_access(curr_state->regs, inst.src,
                                         curr_state->instno, READ, errmsg))
                    return false;
                if (!validate_mem_access(curr_state, inst.dst, &inst, WRITE,
                                         errmsg))
                    return false;
                if (EBPF_SIZE(inst.opcode) == EBPF_SIZE_DW
                    && curr_state->regs[inst.dst].type == STACK_PTR) {
                    // Register spilling
                    int stack_slot = STACK_SIZE + inst.offset;
                    curr_state->stack[stack_slot] = curr_state->regs[inst.src];
                    DEBUG("\tSpilled R%d to stack offset %d\n", inst.src, stack_slot);
                }
                break;

            case EBPF_CLS_LD:
            case EBPF_CLS_LDX:
                if (!validate_reg_access(curr_state->regs, inst.dst,
                                         curr_state->instno, WRITE, errmsg))
                    return false;
                if (inst.opcode == EBPF_OP_LDDW && inst.src == BPF_PSEUDO_MAP_FD) {
                    // Skip next instruction and remember map address:
                    struct ubpf_map *map;
                    curr_state->instno++;
                    uint64_t imm2 = (uint64_t)insts[curr_state->instno].imm;
                    map = (void *)((imm2 << 32) | (uint32_t)inst.imm);
                    curr_state->regs[inst.dst].map = map;
                    curr_state->regs[inst.dst].type = MAP_PTR;
                    curr_state->regs[inst.dst].u.min = 0;
                    curr_state->regs[inst.dst].u.max = 0;
                    curr_state->regs[inst.dst].s.min = 0;
                    curr_state->regs[inst.dst].s.max = 0;
                    DEBUG("\tAssigned map %p to R%d\n", map, inst.dst);
                    break;
                }
                if (!validate_reg_access(curr_state->regs, inst.src,
                                         curr_state->instno, READ, errmsg))
                    return false;
                if (!validate_mem_access(curr_state, inst.src, &inst, READ,
                                         errmsg))
                    return false;
                if (EBPF_SIZE(inst.opcode) == EBPF_SIZE_DW
                    && curr_state->regs[inst.src].type == STACK_PTR) {
                    // Register spilling
                    int stack_slot = STACK_SIZE + inst.offset;
                    curr_state->regs[inst.dst] = curr_state->stack[stack_slot];
                    DEBUG("\tLoaded R%d from stack offset %d\n", inst.dst, stack_slot);
                } else {
                    uint64_t val = inst.imm;
                    if (inst.opcode == EBPF_OP_LDDW) {
                        val |= ((uint64_t)insts[curr_state->instno + 1].imm << 32);
                    }
                    curr_state->regs[inst.dst].type = IMM;
                    curr_state->regs[inst.dst].s.min = val;
                    curr_state->regs[inst.dst].s.max = val;
                    curr_state->regs[inst.dst].u.min = val;
                    curr_state->regs[inst.dst].u.max = val;
                    curr_state->regs[inst.dst].map = NULL;
                    DEBUG("\tR%d now has type IMM, value %ld (%lu)\n", inst.dst, (int64_t)val, val);
                }
                if (inst.opcode == EBPF_OP_LDDW) {
                    // Skip next instruction.
                    curr_state->instno++;
                }
                break;

            case EBPF_CLS_ALU:
            case EBPF_CLS_ALU64:
                if (!validate_alu_op(curr_state, &inst, errmsg))
                    return false;
        }

        curr_state->instno++;
    }
    return true;
}

static int
explore_cfg_edge(enum vertex_status *vertices, enum edge_status *edges,
                 uint32_t v, uint32_t u, enum edge_status branch,
                 char **errmsg) {
    int ret = 0;
    if (vertices[v] >= DISCOVERED && edges[v] >= branch) {
        DEBUG("\tAlready labeled edge %d->%d\n", v, u);
        return 0;
    }
    switch (vertices[u]) {
        case UNDISCOVERED:
            edges[v] = branch;
            DEBUG("\tLabel edge %d->%d\n", v, u);
            vertices[v] = DISCOVERED;
            DEBUG("\tLabel PC %d as discovered\n", v);
            vertices[u] = DISCOVERED;
            DEBUG("\tLabel PC %d as discovered\n", u);
            ret = 1;
            break;
        case EXPLORED:
            edges[v] = branch;
            DEBUG("\tLabel edge %d->%d\n", v, u);
            vertices[v] = DISCOVERED;
            DEBUG("\tLabel PC %d as discovered\n", v);
            ret = 0;
            break;
        case DISCOVERED:
            *errmsg = ubpf_error("back-edge detected from PC %d to PC %d",
                                 v, u);
            ret = -1;
            break;
    }
    return ret;
}

static bool
validate_cfg(const struct ebpf_inst *insts, uint32_t num_insts,
             char **errmsg) {
    uint32_t *s = calloc(num_insts, sizeof(uint32_t));
    enum vertex_status *vertices = calloc(num_insts,
                                          sizeof(enum vertex_status));
    enum edge_status *edges = calloc(num_insts, sizeof(enum edge_status));
    int s_idx = 0, ret;
    uint32_t v, u;
    s[0] = 0;
    vertices[0] = DISCOVERED;
    DEBUG("Label PC 0 as discovered\n");

    while (s_idx >= 0) {
        v = s[s_idx];
        u = v + 1;

        DEBUG("PC=%u, class=0x%x, opcode=0x%x\n", v, EBPF_CLASS(insts[v].opcode), insts[v].opcode);
        if (EBPF_CLASS(insts[v].opcode) == EBPF_CLS_JMP) {
            switch (EBPF_OP(insts[v].opcode)) {
                case EBPF_JMP_JA:
                    u += insts[v].offset;
                    /* fall through */
                case EBPF_JMP_CALL:
                    ret = explore_cfg_edge(vertices, edges, v, u,
                                           BRANCH1_LABELED, errmsg);
                    if (ret < 0) {
                        return false;
                    }
                    if (ret == 1) {
                        s[++s_idx] = u;
                        DEBUG("\tAdding PC %d to stack\n", u);
                        continue;
                    }
                    break;

                case EBPF_JMP_EXIT:
                    break;

                default:
                    // Branch 1:
                    ret = explore_cfg_edge(vertices, edges, v, u,
                                           BRANCH1_LABELED, errmsg);
                    if (ret < 0) {
                        return false;
                    }
                    if (ret == 1) {
                        s[++s_idx] = u;
                        DEBUG("\tAdding PC %d to stack\n", u);
                        continue;
                    }

                    // Branch 2:
                    u += insts[v].offset;
                    ret = explore_cfg_edge(vertices, edges, v, u,
                                           BRANCH2_LABELED, errmsg);
                    if (ret < 0) {
                        return false;
                    }
                    if (ret == 1) {
                        s[++s_idx] = u;
                        DEBUG("\tAdding PC %d to stack\n", u);
                        continue;
                    }
            }
        } else {
            ret = explore_cfg_edge(vertices, edges, v, u, BRANCH1_LABELED,
                                   errmsg);
            if (ret < 0) {
                return false;
            }
            if (ret == 1) {
                s[++s_idx] = u;
                DEBUG("\tAdding PC %d to stack\n", u);
                continue;
            }
        }

        vertices[v] = EXPLORED;
        DEBUG("\tLabel PC %d as explored\n", v);
        s_idx--;
        DEBUG("\tRemoving PC %d from stack\n", v);
    }

    return true;
}

static bool
validate_instructions(const struct ubpf_vm *vm,
                      const struct ebpf_inst *insts,
                      uint32_t num_insts, char **errmsg) {
    int i, new_pc;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_ARSH_IMM:
            if (inst.imm < 0 || inst.imm >= 32) {
                *errmsg = ubpf_error("invalid shift at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_ARSH64_IMM:
            if (inst.imm < 0 || inst.imm >= 64) {
                *errmsg = ubpf_error("invalid shift at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_LDABSB:
        case EBPF_OP_LDABSH:
        case EBPF_OP_LDABSW:
        case EBPF_OP_LDABSDW:
        case EBPF_OP_LDINDB:
        case EBPF_OP_LDINDH:
        case EBPF_OP_LDINDW:
        case EBPF_OP_LDINDDW:
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                *errmsg = ubpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
            new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ubpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ubpf_error("invalid call immediate at PC %d", i);
                return false;
            }
            if (!vm->ext_funcs[inst.imm].func) {
                *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                *errmsg = ubpf_error("division by zero at PC %d", i);
                return false;
            }
            break;

        default:
            *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            *errmsg = ubpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            *errmsg = ubpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

static bool
bounds_check(void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack)
{
    if (mem && (addr >= mem && ((uint64_t)addr + size) <= ((uint64_t)mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && ((uint64_t)addr + size) <= ((uint64_t)stack + STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        fprintf(stderr, "uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\n", type, cur_pc, addr, size);
        fprintf(stderr, "mem %p/%"PRIdSIZE" stack %p/%d\n", mem, mem_len, stack, STACK_SIZE);
        return false;
    }
}

char *
ubpf_error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}
