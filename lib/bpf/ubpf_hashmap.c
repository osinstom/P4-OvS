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

#include <config.h>
#include "ubpf_hashmap.h"

void *
ubpf_hashmap_create(const struct ubpf_map_def *map_def)
{
    struct hashmap *hmap = xzalloc(sizeof(*hmap));

    hmap->nb_buckets = round_up_pow_of_two(map_def->max_entries);
    hmap->count = 0;
    hmap->elem_size = sizeof(struct hmap_elem) + round_up(map_def->key_size, 8)
                             + map_def->value_size;

    hmap->buckets = xmalloc(sizeof(struct ovs_list) * hmap->nb_buckets);
    for (int i = 0; i < hmap->nb_buckets; i++) {
        ovs_list_init(&hmap->buckets[i]);
    }

    return hmap;
}

static inline uint32_t ubpf_hashmap_hash(const void *key, uint32_t key_len)
{
    return hashlittle(key, key_len, 0);
}

static inline struct ovs_list *select_bucket(struct hashmap *hmap,
                                               uint32_t hash)
{
    return &hmap->buckets[hash & (hmap->nb_buckets - 1)];
}

static inline struct hmap_elem* lookup_elem_raw(struct ovs_list *head,
                                                uint32_t hash, const void *key,
                                                uint32_t key_size)
{
    struct hmap_elem *l;
    LIST_FOR_EACH(l, hash_node, head) {
        if (l->hash == hash && !memcmp(&l->key, key, key_size)) {
            return l;
        }
    }
    return NULL;
}

unsigned int
ubpf_hashmap_size(const struct ubpf_map *map)
{
    struct hashmap *hmap = map->data;
    return hmap->count;
}

unsigned int
ubpf_hashmap_dump(const struct ubpf_map *map, void *data)
{
    struct hashmap *hmap = map->data;
    const struct ovs_list *head;
    struct hmap_elem *element;
    int key_size = map->key_size;
    int value_size = map->value_size;
    int key_rounded_size = round_up(map->key_size, 8);

    for(int j = 0; j < hmap->nb_buckets; j++) {
        head = hmap->buckets + j;

        LIST_FOR_EACH(element, hash_node, head) {
            if (element != NULL) {
                void *key_pointer = element->key;
                memcpy(data, key_pointer, key_size);
                data += key_size;

                void *value_pointer = key_pointer + key_rounded_size;
                memcpy(data, value_pointer, value_size);
                data += value_size;
            }
        }
    }

    return hmap->count;
}

void *
ubpf_hashmap_lookup(const struct ubpf_map *map, const void *key)
{
    struct hmap_elem *elem;
    struct hashmap *hmap = map->data;

    uint32_t hash = ubpf_hashmap_hash(key, map->key_size);
    struct ovs_list *head = select_bucket(hmap, hash);
    elem = lookup_elem_raw(head, hash, key, map->key_size);

    if (elem) {
        return elem->key + round_up(map->key_size, 8);
    }
    return NULL;
}

int
ubpf_hashmap_update(struct ubpf_map *map, const void *key, void *value)
{
    struct hmap_elem *old_elem;
    struct hashmap *hmap = map->data;

    uint32_t hash = ubpf_hashmap_hash(key, map->key_size);
    struct ovs_list *head = select_bucket(hmap, hash);
    old_elem = lookup_elem_raw(head, hash, key, map->key_size);

    if (!old_elem && OVS_UNLIKELY(hmap->count >= map->max_entries)) {
        return -4;
    }

    struct hmap_elem *new_elem = xmalloc(hmap->elem_size);
    new_elem->hash = hash;
    memcpy(new_elem->key, key, map->key_size);
    void *value_ptr = new_elem->key + round_up(map->key_size, 8);
    memcpy(value_ptr, value, map->value_size);

    ovs_list_insert(head, &new_elem->hash_node);
    if (old_elem) {
        ovs_list_remove(&old_elem->hash_node);
        free(old_elem);
    } else {
        hmap->count++;
    }

    return 0;
}

int
ubpf_hashmap_delete(struct ubpf_map *map, const void *key)
{
    struct hmap_elem *elem;
    struct hashmap *hmap = map->data;

    uint32_t hash = ubpf_hashmap_hash(key, map->key_size);
    struct ovs_list *head = select_bucket(hmap, hash);
    elem = lookup_elem_raw(head, hash, key, map->key_size);

    if (!elem) {
        return -4;
    }

    ovs_list_remove(&elem->hash_node);
    free(elem);
    hmap->count--;

    return 0;
}
