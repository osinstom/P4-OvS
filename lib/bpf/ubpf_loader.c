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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include "ubpf_int.h"
#include <elf.h>
#include "ubpf_array.c"
#include "ubpf_bf.c"
#include "ubpf_countmin.c"
#include "ubpf_hashmap.h"
#include <config.h>

#define MAX_SECTIONS 32

#ifndef EM_BPF
#define EM_BPF 247
#endif

struct bounds {
    const void *base;
    uint64_t size;
};

struct section {
    const Elf64_Shdr *shdr;
    const void *data;
    uint64_t size;
};

static const void *
bounds_check(struct bounds *bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return (void *)((uint64_t)bounds->base + offset);
}

int
ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_size, char **errmsg)
{
    struct bounds b = { .base=elf, .size=elf_size };
    void *text_copy = NULL, *str_copy = NULL;
    struct ubpf_map *map = NULL;
    int i;

    const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = ubpf_error("not enough data for ELF header");
        goto error;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = ubpf_error("wrong magic");
        goto error;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = ubpf_error("wrong class");
        goto error;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        *errmsg = ubpf_error("wrong byte order");
        goto error;
    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = ubpf_error("wrong version");
        goto error;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = ubpf_error("wrong OS ABI");
        goto error;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = ubpf_error("wrong type, expected relocatable");
        goto error;
    }

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = ubpf_error("wrong machine, expected none or EM_BPF");
        goto error;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        *errmsg = ubpf_error("too many sections");
        goto error;
    }

    /* Parse section headers into an array */
    struct section sections[MAX_SECTIONS];
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }

    /* Find first text section */
    int text_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }
    if (!text_shndx) {
        *errmsg = ubpf_error("text section not found");
        goto error;
    }
    struct section *text = &sections[text_shndx];

    /* Find first .data section */
    int data_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_WRITE)) {
            data_shndx = i;
            break;
        }
    }
    struct section *data = NULL;
    if (data_shndx) {
        data = &sections[data_shndx];
    }

    /* Find first .rodata.str section if any. */
    int str_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_MERGE|SHF_STRINGS)) {
            str_shndx = i;
            break;
        }
    }
    struct section *str = NULL;
    if (str_shndx) {
        str = &sections[str_shndx];

        /* May need to modify text for specifiers, so make a copy */
        str_copy = malloc(str->size);
        if (!str_copy) {
            *errmsg = ubpf_error("failed to allocate memory");
            goto error;
        }
        memcpy(str_copy, str->data, str->size);
    }

    /* May need to modify text for relocations, so make a copy */
    text_copy = xmalloc(text->size);
    memcpy(text_copy, text->data, text->size);

    /* Process each relocation section */
    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *rel = &sections[i];
        if (rel->shdr->sh_type != SHT_REL) {
            continue;
        } else if (rel->shdr->sh_info != text_shndx) {
            continue;
        }

        const Elf64_Rel *rs = rel->data;

        if (rel->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad symbol table section index");
            goto error;
        }

        struct section *symtab = &sections[rel->shdr->sh_link];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(syms[0]);

        if (symtab->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad string table section index");
            goto error;
        }

        struct section *strtab = &sections[symtab->shdr->sh_link];
        const char *strings = strtab->data;

        int j;
        for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
            const Elf64_Rel *r = &rs[j];

            if (ELF64_R_TYPE(r->r_info) != ET_EXEC && ELF64_R_TYPE(r->r_info) != ET_REL) {
                *errmsg = ubpf_error("bad relocation type %u", ELF64_R_TYPE(r->r_info));
                goto error;
            }

            uint32_t sym_idx = ELF64_R_SYM(r->r_info);

            if (sym_idx >= num_syms) {
                *errmsg = ubpf_error("bad symbol index");
                goto error;
            }

            const Elf64_Sym *sym = &syms[sym_idx];

            if (sym->st_name >= strtab->size) {
                *errmsg = ubpf_error("bad symbol name");
                goto error;
            }

            const char *sym_name = strings + sym->st_name;

            if (r->r_offset + 8 > text->size) {
                *errmsg = ubpf_error("bad relocation offset");
                goto error;
            }

            switch(ELF64_R_TYPE(r->r_info)) {
            case 1:
            {
                int sym_shndx = sym->st_shndx;
                if (sym_shndx == data_shndx) {
                    if (!data_shndx) {
                        *errmsg = ubpf_error("missing data section");
                        goto error;
                    }

                    map = ubpf_lookup_registered_map(vm, sym_name);
                    if(!map) {
                        uint64_t sym_data_offset = sym->st_value;
                        if (sym_data_offset + sizeof(struct ubpf_map_def) > data->size) {
                            *errmsg = ubpf_error("bad data offset");
                            goto error;
                        }
                        const struct ubpf_map_def *map_def = (void *)((uint64_t)data->data + sym_data_offset);

                        map = xmalloc(sizeof(struct ubpf_map));
                        map->type = map_def->type;
                        map->key_size = map_def->key_size;
                        map->value_size = map_def->value_size;
                        map->max_entries = map_def->max_entries;

                        switch(map_def->type) {
                        case UBPF_MAP_TYPE_ARRAY:
                            map->ops = ubpf_array_ops;
                            map->data = ubpf_array_create(map_def);
                            break;
                        case UBPF_MAP_TYPE_BLOOMFILTER:
                            map->ops = ubpf_bf_ops;
                            map->data = ubpf_bf_create(map_def);
                            break;
                        case UBPF_MAP_TYPE_COUNTMIN:
                            map->ops = ubpf_countmin_ops;
                            map->data = ubpf_countmin_create(map_def);
                            break;
                        case UBPF_MAP_TYPE_HASHMAP:
                            map->ops = ubpf_hashmap_ops;
                            map->data = ubpf_hashmap_create(map_def);
                            break;
                        default:
                            *errmsg = ubpf_error("unrecognized map type: %d", map_def->type);
                            goto error_map;
                        }

                        if (!map->data) {
                            *errmsg = ubpf_error("failed to allocate memory");
                            goto error_map;
                        }

                        int result = ubpf_register_map(vm, sym_name, map);
                        if (result == -1) {
                            *errmsg = ubpf_error("failed to register variable '%s'", sym_name);
                            goto error_map;
                        }
                    }

                    struct ebpf_inst *inst1 = text_copy + r->r_offset;
                    inst1->src = BPF_PSEUDO_MAP_FD;
                    inst1->imm = (uint32_t)((uint64_t)map);
                    struct ebpf_inst *inst2 = inst1 + 1;
                    inst2->imm = (uint32_t)((uint64_t)map >> 32);

                } else if (sym_shndx == str_shndx) {
                    if (!str_shndx) {
                        *errmsg = ubpf_error("missing string section");
                        goto error;
                    }

                    uint64_t sym_data_offset = sym->st_value;
                    const char *string = (void *)((uint64_t)str_copy + sym_data_offset);
                    size_t str_len = strlen(string);
                    if (sym_data_offset + str_len > str->size) {
                        *errmsg = ubpf_error("bad data offset");
                        goto error;
                    }

                    *(uint32_t *)((uint64_t)text_copy + r->r_offset + 4) = (uint32_t)((uint64_t)string);
                    *(uint32_t *)((uint64_t)text_copy + r->r_offset + sizeof(struct ebpf_inst) + 4) = (uint32_t)((uint64_t)string >> 32);
                }

                break;
            }

            case 2:
            {
                unsigned int imm = ubpf_lookup_registered_function(vm, sym_name);
                if (imm == -1) {
                    *errmsg = ubpf_error("function '%s' not found", sym_name);
                    goto error;
                }

                *(uint32_t *)((uint64_t)text_copy + r->r_offset + 4) = imm;

                break;
            }

            default: ;
            }
        }
    }

    int rv = ubpf_load(vm, text_copy, sections[text_shndx].size, errmsg);
    free(text_copy);
    return rv;

error_map:
    free(map);
error:
    free(text_copy);
    return -1;
}
