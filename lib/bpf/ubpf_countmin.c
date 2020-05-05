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
#include <string.h>

#include <config.h>
#include "util.h"

#include "lookup3.h"
#include "ubpf_int.h"

#ifndef min
#define min(a,b) ((a < b)? a : b)
#endif

void *ubpf_countmin_create(const struct ubpf_map_def *map_def);
static void *ubpf_countmin_lookup(const struct ubpf_map *map, const void *key);
static int ubpf_countmin_add(struct ubpf_map *map, void *value);

struct countmin_sketch {
    unsigned int nb_columns;
    unsigned int nb_rows;
    void *current_count;
    uint32_t counters[];
};

const struct ubpf_map_ops ubpf_countmin_ops = {
    .map_lookup = ubpf_countmin_lookup,
    .map_update = NULL,
    .map_delete = NULL,
    .map_add = ubpf_countmin_add,
};

void *
ubpf_countmin_create(const struct ubpf_map_def *map_def)
{
    int size_bitmap = sizeof(uint32_t) * map_def->nb_hash_functions *
                      map_def->max_entries;
    struct countmin_sketch *countmin = xmalloc(sizeof(struct countmin_sketch) +
                                              size_bitmap);

    /* Whatever the value size, we always return a uint32_t,
     * so we need to zero out the rest of the memory buffer.
     */
    countmin->current_count = xcalloc(1, map_def->value_size);

    countmin->nb_columns = map_def->nb_hash_functions;
    countmin->nb_rows = map_def->max_entries;
    memset(countmin->counters, 0, size_bitmap);

    return countmin;
}

static void *
ubpf_countmin_lookup(const struct ubpf_map *map, const void *value)
{
    unsigned int i;
    struct countmin_sketch *countmin = map->data;
    uint32_t h1 = 0, h2 = 0, hash;

    uint32_t *count = countmin->current_count;
    *count = UINT32_MAX;

    if (countmin->nb_columns == 1) {
        h1 = hashlittle(value, map->value_size, 0);
    } else {
        hashlittle2(value, map->value_size, &h1, &h2);
    }
    for (i=0; i<countmin->nb_columns; i++) {
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
        hash %= countmin->nb_rows;
        *count = min(*count,
                    countmin->counters[i * countmin->nb_columns + hash]);
    }

    return count;
}

static int
ubpf_countmin_add(struct ubpf_map *map, void *value)
{
    unsigned int i;
    struct countmin_sketch *countmin = map->data;
    uint32_t h1 = 0, h2 = 0, hash;
    if (countmin->nb_columns == 1) {
        h1 = hashlittle(value, map->value_size, 0);
    } else {
        hashlittle2(value, map->value_size, &h1, &h2);
    }
    for (i=0; i<countmin->nb_columns; i++) {
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
        hash %= countmin->nb_rows;
        countmin->counters[i * countmin->nb_columns + hash]++;
    }
    return 0;
}
