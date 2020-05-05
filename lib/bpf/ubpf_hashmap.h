/*
 * Copyright 2018 Orange
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
#ifndef UBPF_HASHMAP_H
#define UBPF_HASHMAP_H 1

#include "util.h"
#include "openvswitch/list.h"

#include "lookup3.h"
#include "ubpf_int.h"

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
/*
 * Compute the next highest power of 2 of 32-bit x.
 */
#define round_up_pow_of_two(x) \
    ({ uint32_t v = x;         \
    v--;                       \
    v |= v >> 1;               \
    v |= v >> 2;               \
    v |= v >> 4;               \
    v |= v >> 8;               \
    v |= v >> 16;              \
    ++v; })

void *ubpf_hashmap_create(const struct ubpf_map_def *map_def);
unsigned int ubpf_hashmap_size(const struct ubpf_map *map);
unsigned int ubpf_hashmap_dump(const struct ubpf_map *map, void *data);
void *ubpf_hashmap_lookup(const struct ubpf_map *map, const void *key);
int ubpf_hashmap_update(struct ubpf_map *map, const void *key, void *value);
int ubpf_hashmap_delete(struct ubpf_map *map, const void *key);

struct hashmap {
    struct ovs_list *buckets;
    uint32_t count;
    uint32_t nb_buckets;
    uint32_t elem_size;
};

struct hmap_elem {
    struct ovs_list hash_node;
    uint32_t hash;
    char key[0] OVS_ALIGNED_VAR(8);
};

static const struct ubpf_map_ops ubpf_hashmap_ops = {
    .map_size = ubpf_hashmap_size,
    .map_dump = ubpf_hashmap_dump,
    .map_lookup = ubpf_hashmap_lookup,
    .map_update = ubpf_hashmap_update,
    .map_delete = ubpf_hashmap_delete,
    .map_add = NULL,
};

#define BPF_KEY_IS_HASH 1

#endif