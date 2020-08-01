/*
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

#ifndef BPF_H
#define BPF_H 1

#include <stdint.h>

#include "bpf/lookup3.h"
#include "bpf/ubpf.h"
#include "bpf/ubpf_int.h"
#include "dp-packet.h"
#include "util.h"

typedef enum OVS_PACKED_ENUM {
    BPF_UNKNOWN = 0,
    BPF_MATCH,
    BPF_NO_MATCH,
} bpf_result;

struct ubpf_vm *create_ubpf_vm(const ovs_be16 prog_id);
bool load_bpf_prog(struct ubpf_vm *vm, size_t code_len, const char *code);
void *ubpf_map_lookup(const struct ubpf_map *map, void *key);
int ubpf_map_update(struct ubpf_map *map, const void *key, void *item);
int ubpf_map_dump(struct ubpf_map *map, char *data);
void *ubpf_adjust_head(void* ctx, int offset);
void *ubpf_packet_data(void *ctx);

static inline bpf_result
ubpf_handle_packet(struct ubpf_vm *vm, struct standard_metadata *md, struct dp_packet *packet)
{
    md->packet_length = dp_packet_size(packet);
    uint64_t ret = vm->jitted(packet, md);
    return (ret == 1)? BPF_MATCH : BPF_NO_MATCH;
}

static inline bool
ubpf_is_empty(struct ubpf_vm *vm)
{
    return vm->insts == NULL;
}

#endif
