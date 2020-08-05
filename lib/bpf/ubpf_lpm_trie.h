/*
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

#ifndef UBPF_LPM_TRIE_H
#define UBPF_LPM_TRIE_H 1

#include "ubpf_int.h"
#include "util.h"

void *ubpf_lpm_trie_create(const struct ubpf_map_def *map_def);
int ubpf_lpm_trie_update(struct ubpf_map *map, const void *key, void *value);
void *ubpf_lpm_trie_lookup(const struct ubpf_map *map, const void *_key);
unsigned int ubpf_lpm_trie_size(const struct ubpf_map *map);
void ubpf_lpm_trie_destroy(struct ubpf_map *map);
int ubpf_lpm_trie_delete(struct ubpf_map *map, const void *key);
unsigned int ubpf_lpm_trie_dump(const struct ubpf_map *map, char *data);

static const struct ubpf_map_ops ubpf_lpm_trie_ops = {
    .map_size = ubpf_lpm_trie_size,
    .map_dump = ubpf_lpm_trie_dump,
    .map_lookup = ubpf_lpm_trie_lookup,
    .map_update = ubpf_lpm_trie_update,
    .map_delete = ubpf_lpm_trie_delete,
    .map_add = NULL,
    .map_destroy = ubpf_lpm_trie_destroy,
};

struct lpm_trie_key {
    uint32_t prefix_len;
    uint8_t  data[0];
};

struct lpm_trie_node {
    struct lpm_trie_node *child[2];
    uint32_t             prefix_len;
    uint32_t             flags;
    uint8_t              data[0];
};

struct lpm_trie {
    struct lpm_trie_node *root;
    size_t               n_entries;
    size_t               max_prefixlen;
    size_t               data_size;
};



#endif
