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

#include <config.h>
#include <stdio.h>
#include <errno.h>

#include "bpf.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(bpf)

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

#define MAX_PRINTF_LENGTH 80

static void register_functions(struct ubpf_vm *vm);

struct ubpf_vm *
create_ubpf_vm(const ovs_be16 prog)
{
    struct ubpf_vm *vm = ubpf_create(prog);
    if (!vm) {
        VLOG_WARN_RL(&rl, "Failed to create VM\n");
        return NULL;
    }

    register_functions(vm);

    return vm;
}

bool
load_bpf_prog(struct ubpf_vm *vm, size_t code_len, const char *code)
{
    char *errmsg;
    int rv = ubpf_load_elf(vm, code, code_len, &errmsg);
    if (rv < 0) {
        VLOG_WARN_RL(&rl, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        return false;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (fn == NULL) {
        VLOG_WARN_RL(&rl, "Failed to compile: %s\n", errmsg);
        free(errmsg);
        return false;
    }

    return true;
}

void *
ubpf_map_lookup(const struct ubpf_map *map, void *key)
{
    if (OVS_UNLIKELY(!map)) {
        return NULL;
    }
    if (OVS_UNLIKELY(!map->ops.map_lookup)) {
        return NULL;
    }
    if (OVS_UNLIKELY(!key)) {
        return NULL;
    }
    return map->ops.map_lookup(map, key);
}

static struct ubpf_func_proto ubpf_map_lookup_proto = {
    .func = (ext_func)ubpf_map_lookup,
    .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR | UNKNOWN,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
            },
    .ret = MAP_VALUE_PTR | NULL_VALUE,
};

int
ubpf_map_update(struct ubpf_map *map, const void *key, void *item)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_update)) {
        return -2;
    }
    if (OVS_UNLIKELY(!key)) {
        return -3;
    }
    if (OVS_UNLIKELY(!item)) {
        return -4;
    }
    return map->ops.map_update(map, key, item);
}

static struct ubpf_func_proto ubpf_map_update_proto = {
    .func = (ext_func)ubpf_map_update,
    .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
            },
    .ret = UNKNOWN,
};

int
ubpf_map_dump(struct ubpf_map *map, char *data)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }

    if (OVS_UNLIKELY(!map->ops.map_dump)) {
        return -2;
    }

    return map->ops.map_dump(map, data);
}

unsigned int
ubpf_map_size(struct ubpf_map *map)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }

    if (OVS_UNLIKELY(!map->ops.map_size)) {
        return -2;
    }

    return map->ops.map_size(map);
}

static int
ubpf_map_add(struct ubpf_map *map, void *item)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_add)) {
        return -2;
    }
    if (OVS_UNLIKELY(!item)) {
        return -3;
    }
    return map->ops.map_add(map, item);
}

static struct ubpf_func_proto ubpf_map_add_proto = {
    .func = (ext_func)ubpf_map_add,
    .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
                0xff,
            },
    .ret = UNKNOWN,
};

static int
ubpf_map_delete(struct ubpf_map *map, const void *key)
{
    if (OVS_UNLIKELY(!map)) {
        return -1;
    }
    if (OVS_UNLIKELY(!map->ops.map_delete)) {
        return -2;
    }
    if (OVS_UNLIKELY(!key)) {
        return -3;
    }
    return map->ops.map_delete(map, key);
}

static struct ubpf_func_proto ubpf_map_delete_proto = {
    .func = (ext_func)ubpf_map_delete,
    .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
            },
    .ret = UNKNOWN,
};

static void
ubpf_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char str[MAX_PRINTF_LENGTH];
    if (vsnprintf(str, MAX_PRINTF_LENGTH, fmt, args) >= 0)
        VLOG_INFO("%s", str);
    va_end(args);
}

static struct ubpf_func_proto ubpf_printf_proto = {
    .func = (ext_func)ubpf_printf,
    .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
            },
    .ret = UNINIT,
};

static uint64_t
ubpf_time_get_ns(void)
{
    struct timespec curr_time = {0, 0};
    uint64_t curr_time_ns = 0;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
    return curr_time_ns;
}

static struct ubpf_func_proto ubpf_time_get_ns_proto = {
    .func = (ext_func)ubpf_time_get_ns,
    .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
            },
    .ret = UNKNOWN,
};

static uint32_t
ubpf_hash(void *item, uint64_t size)
{
    return hashlittle(item, (uint32_t)size, 0);
}

static struct ubpf_func_proto ubpf_hash_proto = {
    .func = (ext_func)ubpf_hash,
    .arg_types = {
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                IMM,
                0xff,
                0xff,
                0xff,
            },
    .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                0xff,
                0xff,
                0xff,
            },
    .ret = UNKNOWN,
};

void *
ubpf_adjust_head(void* ctx, int offset) {
    struct dp_packet *packet = (struct dp_packet *) ctx;

    void *pkt = NULL;
    if (offset >= 0)  // encapsulation
        pkt = dp_packet_push_zeros(packet, offset);
    else {  // decapsulation
        dp_packet_reset_packet(packet, abs(offset));
        pkt = dp_packet_data(packet);
    }

    return pkt;
}

static struct ubpf_func_proto ubpf_adjust_head_proto = {
    .func = (ext_func)ubpf_adjust_head,
    .arg_types = {
            CTX_PTR,
            IMM,
            0xff,
            0xff,
            0xff,
    },
    .arg_sizes = {
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
    },
    .ret = PKT_PTR,
};

void *
ubpf_packet_data(void *ctx)
{
    struct dp_packet *packet = (struct dp_packet *) ctx;
    return dp_packet_data(packet);
}

static struct ubpf_func_proto ubpf_packet_data_proto = {
    .func = (ext_func)ubpf_packet_data,
    .arg_types = {
            CTX_PTR,
            0xff,
            0xff,
            0xff,
            0xff,
    },
    .arg_sizes = {
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
    },
    .ret = PKT_PTR,
};

static uint32_t
ubpf_get_rss_hash(void *ctx)
{
    struct dp_packet *packet = (struct dp_packet *) ctx;
    return dp_packet_get_rss_hash(packet);
}

static struct ubpf_func_proto ubpf_get_rss_hash_proto = {
        .func = (ext_func)ubpf_get_rss_hash,
        .arg_types = {
                PKT_PTR,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register_function(vm, 1, "ubpf_map_lookup", ubpf_map_lookup_proto);
    ubpf_register_function(vm, 2, "ubpf_map_update", ubpf_map_update_proto);
    ubpf_register_function(vm, 3, "ubpf_map_delete", ubpf_map_delete_proto);
    ubpf_register_function(vm, 4, "ubpf_map_add", ubpf_map_add_proto);
    ubpf_register_function(vm, 5, "ubpf_time_get_ns", ubpf_time_get_ns_proto);
    ubpf_register_function(vm, 6, "ubpf_hash", ubpf_hash_proto);
    ubpf_register_function(vm, 7, "ubpf_printf", ubpf_printf_proto);
    ubpf_register_function(vm, UBPF_ADJUST_HEAD_ID, "ubpf_adjust_head", ubpf_adjust_head_proto);
    ubpf_register_function(vm, 9, "ubpf_packet_data", ubpf_packet_data_proto);
    ubpf_register_function(vm, 10, "ubpf_get_rss_hash", ubpf_get_rss_hash_proto);
}
