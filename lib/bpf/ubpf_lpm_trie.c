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


#include <config.h>
#include <errno.h>

#include "ubpf_lpm_trie.h"
#include "openvswitch/vlog.h"

#define LPM_TREE_NODE_FLAG_IM 1
VLOG_DEFINE_THIS_MODULE(ubpf_lpm_trie);

void *
ubpf_lpm_trie_create(const struct ubpf_map_def *map_def)
{
    struct lpm_trie *trie;

    /* TODO: sanity checks. */

    trie = xzalloc(sizeof *trie);
    if (!trie) {
        return NULL;
    }

    trie->data_size = map_def->key_size - offsetof(struct lpm_trie_key, data);
    if (trie->data_size == 0) {
        VLOG_ERR("Invalid key size provided");
        return NULL;
    }

    trie->max_prefixlen = trie->data_size * 8;

    return trie;
}

static struct lpm_trie_node *
lpm_trie_node_alloc(const struct lpm_trie *trie, const void *value, size_t value_size)
{
    struct lpm_trie_node *node;
    size_t size = sizeof(struct lpm_trie_node) + trie->data_size;

    if (value) {
        size += value_size;
    }

    node = xzalloc(size);

    if (!node) {
        return NULL;
    }

    if (value) {
        memcpy(node->data + trie->data_size, value, value_size);
    }

    return node;
}

static int
fls64(uint64_t x)
{
    int bitpos = -1;
    asm("bsrq %1,%q0"
    : "+r" (bitpos)
    : "rm" (x));
    return bitpos + 1;
}

static inline int extract_bit(const uint8_t *data, size_t index)
{
    return !!(data[index / 8] & (1 << (7 - (index % 8))));
}

static size_t
longest_prefix_match(const struct lpm_trie *trie,
                     const struct lpm_trie_node *node,
                     const struct lpm_trie_key *key)
{
    uint32_t limit = node->prefix_len;
    uint32_t prefix_len = 0, i = 0;

    while (trie->data_size >= i + 4) {
        uint32_t diff = (*(uint32_t *) &node->data[i] ^ *(uint32_t *) &key->data[i]);

        prefix_len += 32 - fls64((uint64_t) diff);
        if (prefix_len >= limit) {
            return limit;
        }

        if (diff) {
            return prefix_len;
        }

        i += 4;
    }

    if (trie->data_size >= i + 2) {
        uint16_t diff = (*(uint16_t *)&node->data[i] ^ *(uint16_t *)&key[i]);
        prefix_len += 16 - fls64((uint64_t) diff);
        if (prefix_len >= limit)
            return limit;
        if (diff)
            return prefix_len;
        i += 2;
    }

    if (trie->data_size >= i + 1) {
        prefix_len += 8 - fls64((uint64_t) (node->data[i] ^ key->data[i]));
        if (prefix_len >= limit)
            return limit;
    }

    return prefix_len;
}

int
ubpf_lpm_trie_update(struct ubpf_map *map, const void *_key, void *value)
{
    int error = 0;
    struct lpm_trie *trie = map->data;
    struct lpm_trie_node *node = NULL, *im_node = NULL, *new_node = NULL;
    struct lpm_trie_node **slot;

    const struct lpm_trie_key *key = _key;
    unsigned int next_bit;
    size_t match_len = 0;

    if (key->prefix_len > trie->max_prefixlen) {
        return -EINVAL;
    }

    if (trie->n_entries == map->max_entries) {
        return ENOSPC;
    }

    new_node = lpm_trie_node_alloc(trie, value, map->value_size);
    if (!new_node) {
        return ENOMEM;
    }

    trie->n_entries++;

    new_node->prefix_len = key->prefix_len;
    new_node->child[0] = NULL;
    new_node->child[1] = NULL;

    memcpy(new_node->data, key->data, trie->data_size);

    /* Now find a slot to attach the new node. To do that, walk the tree
     * from the root and match as many bits as possible for each node until
     * we either find an empty slot or a slot that needs to be replaced by
     * an intermediate node.
     */
    slot = &trie->root;
    node = *slot;

    while ( (node = *slot) ) {
        match_len = longest_prefix_match(trie, node, key);

        if (node->prefix_len != match_len ||
            node->prefix_len == key->prefix_len ||
            node->prefix_len == trie->max_prefixlen) {
            break;
        }

        next_bit = extract_bit(key->data, node->prefix_len);
        slot = &node->child[next_bit];
    }

    if (!node) {
        *slot = new_node;
        goto out;
    }

    /* If the slot we picked already exists, replace it with @new_node
     * which already has the correct data array set.
     */
    if (node->prefix_len == match_len) {
        new_node->child[0] = node->child[0];
        new_node->child[1] = node->child[1];

        if (!(node->flags & LPM_TREE_NODE_FLAG_IM))
            trie->n_entries--;

        *slot = new_node;
        free(node);

        goto out;
    }

    /* If the new node matches the prefix completely, it must be inserted
     * as an ancestor. Simply insert it between @node and *@slot.
     */
    if (match_len == key->prefix_len) {
        next_bit = extract_bit(node->data, match_len);
        new_node->child[next_bit] = node;
        *slot = new_node;
        goto out;
    }

    im_node = lpm_trie_node_alloc(trie, NULL, 0);
    if (!im_node) {
        error = ENOMEM;
        goto out;
    }

    im_node->prefix_len = match_len;
    im_node->flags |= LPM_TREE_NODE_FLAG_IM;
    memcpy(im_node->data, node->data, trie->data_size);

    /* Now determine which child to install in which slot */
    if (extract_bit(key->data, match_len)) {
        im_node->child[0] = node;
        im_node->child[1] = new_node;
    } else {
        im_node->child[0] = new_node;
        im_node->child[1] = node;
    }

    *slot = im_node;

out:
    if (error) {
        if (new_node) {
            trie->n_entries--;
        }
        free(new_node);
        free(im_node);
    }

    return error;
}

void *
ubpf_lpm_trie_lookup(const struct ubpf_map *map, const void *_key)
{
    struct lpm_trie *trie = map->data;
    struct lpm_trie_node *node, *found = NULL;
    const struct lpm_trie_key *key = _key;

    /* Start walking the trie from the root node ... */
    for (node = trie->root; node;) {
        unsigned int next_bit;
        size_t match_len;

        /* Determine the longest prefix of @node that matches @key.
         * If it's the maximum possible prefix for this trie, we have
         * an exact match and can return it directly.
         */
        match_len = longest_prefix_match(trie, node, key);
        if (match_len == trie->max_prefixlen) {
            found = node;
            break;
        }

        /* If the number of bits that match is smaller than the prefix
         * length of @node, bail out and return the node we have seen
         * last in the traversal (ie, the parent).
         */
        if (match_len < node->prefix_len) {
            break;
        }

        if (!(node->flags & LPM_TREE_NODE_FLAG_IM)) {
            found = node;
        }

        /* If the node match is fully satisfied, let's see if we can
         * become more specific. Determine the next bit in the key and
         * traverse down.
         */
        next_bit = extract_bit(key->data, node->prefix_len);
        node = node->child[next_bit];
    }

    if (!found) {
        return NULL;
    }

    return found->data + trie->data_size;
}

void
ubpf_lpm_trie_destroy(struct ubpf_map *map)
{
    struct lpm_trie *trie = map->data;
    struct lpm_trie_node **slot;
    struct lpm_trie_node *node;

    for (;;) {
        slot = &trie->root;

        for (;;) {
            node = *slot;
            if (!node)
                goto out;

            if (node->child[0]) {
                slot = &node->child[0];
                continue;
            }

            if (node->child[1]) {
                slot = &node->child[1];
            }

            free(node);
            *slot = NULL;
            break;
        }
    }

out:
    free(trie);
}

unsigned int
ubpf_lpm_trie_size(const struct ubpf_map *map)
{
    struct lpm_trie *trie = map->data;
    return trie->n_entries;
}

int
ubpf_lpm_trie_delete(struct ubpf_map *map, const void *_key)
{
    struct lpm_trie *trie = map->data;
    const struct lpm_trie_key *key = _key;
    struct lpm_trie_node **trim, **trim2;
    struct lpm_trie_node *node, *parent;
    unsigned int next_bit;
    size_t match_len = 0;
    int error = 0;

    if (key->prefix_len > trie->max_prefixlen)
        return -EINVAL;

    /* Walk the tree looking for an exact key/length match and keeping
     * track of the path we traverse.  We will need to know the node
     * we wish to delete, and the slot that points to the node we want
     * to delete.  We may also need to know the nodes parent and the
     * slot that contains it.
     */
    trim = &trie->root;
    trim2 = trim;
    parent = NULL;
    node = *trim;
    while ( (node = *trim) ) {
        match_len = longest_prefix_match(trie, node, key);

        if (node->prefix_len != match_len ||
            node->prefix_len == key->prefix_len)
            break;

        parent = node;
        trim2 = trim;
        next_bit = extract_bit(key->data, node->prefix_len);
        trim = &node->child[next_bit];
    }

    if (!node || node->prefix_len != key->prefix_len ||
        node->prefix_len != match_len ||
            (node->flags & LPM_TREE_NODE_FLAG_IM)) {
        return ENOENT;
    }

    trie->n_entries--;

    /* If the node we are removing has two children, simply mark it
     * as intermediate and we are done.
     */
    if (node->child[0] && node->child[1]) {
        node->flags |= LPM_TREE_NODE_FLAG_IM;
        return error;
    }

    /* If the parent of the node we are about to delete is an intermediate
     * node, and the deleted node doesn't have any children, we can delete
     * the intermediate parent as well and promote its other child
     * up the tree.  Doing this maintains the invariant that all
     * intermediate nodes have exactly 2 children and that there are no
     * unnecessary intermediate nodes in the tree.
     */
    if (parent && (parent->flags & LPM_TREE_NODE_FLAG_IM) &&
        !node->child[0] && !node->child[1]) {
        if (node == parent->child[0]) {
            *trim2 = parent->child[1];
        } else {
            *trim2 = parent->child[0];
        }
        free(parent);
        free(node);
        return error;
    }

    /* The node we are removing has either zero or one child. If there
     * is a child, move it into the removed node's slot then delete
     * the node.  Otherwise just clear the slot and delete the node.
     */
    if (node->child[0]) {
        *trim = node->child[0];
    } else if (node->child[1]) {
        *trim = node->child[1];
    } else {
        *trim = NULL;
    }
    free(node);

    return error;
}

static void
dump_postorder(const struct ubpf_map *map, struct lpm_trie_node *node, char **data, unsigned int *nr_entries)
{
    if (!node) {
        return;
    }

    dump_postorder(map, node->child[0], data, nr_entries);
    dump_postorder(map, node->child[1], data, nr_entries);

    /*
     * If node in an intermediate one, don't count.
     */
    if ((node->flags & LPM_TREE_NODE_FLAG_IM)) {
        return;
    }

    *nr_entries += 1;

    uint32_t data_size = map->key_size - offsetof(struct lpm_trie_key, data);

    ovs_be32 plen = htonl(node->prefix_len);
    memcpy(*data, &plen, sizeof(node->prefix_len));
    *data += sizeof(node->prefix_len);

    memcpy(*data, node->data, map->key_size-sizeof(node->prefix_len));
    *data += map->key_size-sizeof(node->prefix_len);

    memcpy(*data, node->data + data_size, map->value_size);
    *data += map->value_size;
}

unsigned int
ubpf_lpm_trie_dump(const struct ubpf_map *map, char *data)
{
    struct lpm_trie *trie = map->data;

    unsigned int nr_entries = 0;
    char **data_ptr = &data;
    dump_postorder(map, trie->root, data_ptr, &nr_entries);

    return nr_entries;
}
