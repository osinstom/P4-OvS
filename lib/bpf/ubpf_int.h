/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include "ubpf.h"
#include "ebpf.h"
#include "openvswitch/hmap.h"

#define MAX_INSTS 65536
#define STACK_SIZE 1024
#define NB_FUNC_ARGS 5
#define MAX_SIZE_ARG 8
#define UBPF_ADJUST_HEAD_ID 8
#define BPF_PSEUDO_MAP_FD 1

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

enum ubpf_reg_type {
    UNINIT        = 0,
    UNKNOWN       = 1,
    NULL_VALUE    = 2,
    IMM           = 4,
    MAP_PTR       = 8,
    MAP_VALUE_PTR = 16,
    PKT_PTR       = 32,
    PKT_SIZE      = 64,
    STACK_PTR     = 128,
    CTX_PTR       = 256,
};

enum ubpf_arg_size {
    SIZE_64 = 0,
    SIZE_MAP_KEY,
    SIZE_MAP_VALUE,
    SIZE_PTR_MAX,
};

struct ubpf_func_proto {
    ext_func func;
    enum ubpf_reg_type arg_types[NB_FUNC_ARGS];
    enum ubpf_arg_size arg_sizes[NB_FUNC_ARGS];
    enum ubpf_reg_type ret;
};

enum ubpf_map_type {
    UBPF_MAP_TYPE_ARRAY = 1,
    UBPF_MAP_TYPE_BLOOMFILTER = 2,
    UBPF_MAP_TYPE_COUNTMIN = 3,
    UBPF_MAP_TYPE_HASHMAP = 4,
};

struct ubpf_map_def {
    enum ubpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int nb_hash_functions;
};

struct ubpf_map;

struct ubpf_map_ops {
    unsigned int (*map_size)(const struct ubpf_map *map);
    unsigned int (*map_dump)(const struct ubpf_map *map, void *data);
    void *(*map_lookup)(const struct ubpf_map *map, const void *key);
    int (*map_update)(struct ubpf_map *map, const void *key, void *value);
    int (*map_delete)(struct ubpf_map *map, const void *key);
    int (*map_add)(struct ubpf_map *map, void *value);
};

struct ubpf_map {
    enum ubpf_map_type type;
    struct ubpf_map_ops ops;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    void *data;
};

struct ubpf_vm {
    ovs_be16 prog_id;
    struct hmap_node hmap_node;
    struct ebpf_inst *insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    struct ubpf_func_proto *ext_funcs;
    const char **ext_func_names;
    struct ubpf_map **ext_maps;
    const char **ext_map_names;
    uint16_t nb_maps;
    unsigned long long int loaded_at;
};

char *ubpf_error(const char *fmt, ...);
unsigned int ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name);
struct ubpf_map *ubpf_lookup_registered_map(struct ubpf_vm *vm, const char *name);

#endif
