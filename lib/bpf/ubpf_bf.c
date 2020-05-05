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
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <config.h>
#include "util.h"

#include "lookup3.h"
#include "ubpf_int.h"

void *ubpf_bf_create(const struct ubpf_map_def *map_def);
static void *ubpf_bf_lookup(const struct ubpf_map *map, const void *value);
static int ubpf_bf_add(struct ubpf_map *map, void *value);

struct bloom_filter {
    unsigned int nb_hash_functions;
    int ret_true;
    int ret_false;
    uint8_t bits[];
};

const struct ubpf_map_ops ubpf_bf_ops = {
    .map_lookup = ubpf_bf_lookup,
    .map_update = NULL,
    .map_delete = NULL,
    .map_add = ubpf_bf_add,
};

void *
ubpf_bf_create(const struct ubpf_map_def *map_def)
{
    int nb_bytes = map_def->max_entries / 8;
    struct bloom_filter* bf = xmalloc(sizeof(struct bloom_filter) +
                                    sizeof(uint8_t) * nb_bytes +
                                    sizeof(int) * 3);
    bf->nb_hash_functions = map_def->nb_hash_functions;
    bf->ret_true = 1;
    bf->ret_false = 0;
    memset(bf->bits, 0, nb_bytes);
    return bf;
}

static void *
ubpf_bf_lookup(const struct ubpf_map *map, const void *value)
{
    unsigned int i;
    struct bloom_filter *bf = map->data;
    uint32_t h1 = 0, h2 = 0, hash;
    if (bf->nb_hash_functions == 1) {
        h1 = hashlittle(value, map->value_size, 0);
    } else {
        hashlittle2(value, map->value_size, &h1, &h2);
    }
    for (i=0; i<bf->nb_hash_functions; i++) {
        switch (i) {
        case 0:
            hash = h1;
            break;
        case 1:
            hash = h2;
            break;
        default:
            hash = h1 + i * h2;
        }
        hash %= map->max_entries * 8;
        if (!(bf->bits[hash / 8] & 1 << hash % 8)) {
            return &bf->ret_false;
        }
    }
    return &bf->ret_true;
}

static int
ubpf_bf_add(struct ubpf_map *map, void *value)
{
    unsigned int i;
    struct bloom_filter *bf = map->data;
    uint32_t h1 = 0, h2 = 0, hash;
    if (bf->nb_hash_functions == 1) {
        h1 = hashlittle(value, map->value_size, 0);
    } else {
        hashlittle2(value, map->value_size, &h1, &h2);
    }
    for (i=0; i<bf->nb_hash_functions; i++) {
        switch (i) {
        case 0:
            hash = h1;
            break;
        case 1:
            hash = h2;
            break;
        default:
            hash = h1 + i * h2;
        }
        hash %= map->max_entries * 8;
        bf->bits[hash / 8] |= 1 << hash % 8;
    }
    return 0;
}
