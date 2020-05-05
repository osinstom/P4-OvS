#ifndef BPF_H
#define BPF_H 1

#include <stdint.h>

#include "util.h"
#include "bpf/ubpf.h"
#include "bpf/ubpf_int.h"
#include "dp-packet.h"
#include "bpf/lookup3.h"

typedef enum OVS_PACKED_ENUM {
    BPF_UNKNOWN = 0,
    BPF_MATCH,
    BPF_NO_MATCH,
} bpf_result;

struct ubpf_vm *create_ubpf_vm(const ovs_be16 prog_id);
bool load_bpf_prog(struct ubpf_vm *vm, size_t code_len, char *code);
void *ubpf_map_lookup(const struct ubpf_map *map, void *key);
int ubpf_map_update(struct ubpf_map *map, const void *key, void *item);

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
