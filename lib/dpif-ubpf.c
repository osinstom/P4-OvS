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
#include <errno.h>

#include "bpf.h"
#include "dpif-netdev.h"
#include "dpif-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/shash.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "p4rt-objects.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(dpif_ubpf);

/* ## --------------------------------------- ## */
/* ## dpif-ubpf helper structures definition. ## */
/* ## --------------------------------------- ## */

struct dp_prog {
    struct cmap_node cmap_node; /* Within dp_ubpf.dp_progs_port_map */

    uint32_t id;
    struct ubpf_vm *vm;

    const pi_p4info_t *p4info;

    struct hmap table_ids;   /* Provide mapping between table IDs used by Control Plane API and uBPF */
    struct hmap action_ids;  /* Provide mapping between action IDs used by Control Plane API and uBPF */

    bool default_action_set; /* Indicate if default action has been set. */
};

struct dp_ubpf {
    struct dp_netdev dp_netdev;
    const char *const name;

    /* Stores the association between an dp_netdev's port and associated uBPF program. */
    struct cmap dp_progs_port_map;
};

/* Interface to ubpf-based datapath. */
struct dpif_ubpf {
    struct dpif_netdev dpif_netdev;
    struct dp_ubpf *dp;
};

struct dp_netdev_action_flow {
    struct cmap_node node;
    uint32_t hash;
    struct nlattr *action;

    struct packet_batch_per_action *action_batch;
};

struct packet_batch_per_action {
    struct dp_packet_batch output_batch;
    struct dp_netdev_action_flow *action;
};

struct dpif_table_id {
    struct hmap_node hmap_node;
    uint32_t table_id;
    uint32_t dp_table_id;
};

struct dpif_action_id {
    struct hmap_node hmap_node;
    uint32_t action_id;
    uint32_t dp_action_id;
};

/* ## ------------------------------------------ ## */
/* ## Global (shared) objects used by dpif-ubpf. ## */
/* ## ------------------------------------------ ## */

/* Protects against changes to 'dp_ubpfs'. */
static struct ovs_mutex dp_ubpf_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_ubpfs OVS_GUARDED_BY(dp_ubpf_mutex)
        = SHASH_INITIALIZER(&dp_ubpfs);

/* Protects against changes to 'dp_progs'. */
static struct ovs_mutex dp_prog_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_prog's.
 * According to PI library 256 is the maximum number of P4 devices. */
static struct dp_prog *dp_progs[256] = { };

/* ## ------------------------- ## */
/* ## Prototypes for functions. ## */
/* ## ------------------------- ## */

static void dp_prog_destroy_(struct dp_prog *prog);

/* ## --------------------------- ## */
/* ## dpif-ubpf helper functions. ## */
/* ## --------------------------- ## */

static struct dp_ubpf *
dp_ubpf_cast(struct dp_netdev *dp_netdev)
{
    return CONTAINER_OF(dp_netdev, struct dp_ubpf, dp_netdev);
}

static struct dpif_ubpf *
dpif_ubpf_cast(const struct dpif *dpif)
{
    return CONTAINER_OF(dpif, struct dpif_ubpf, dpif_netdev.dpif);
}

static int
translate_table_id(struct dp_prog *prog, uint32_t *table_id)
{
    struct dpif_table_id *tbl;
    uint32_t id = *table_id;

    HMAP_FOR_EACH_WITH_HASH (tbl, hmap_node, hash_int(id, 0),
                             &prog->table_ids) {
        if (tbl->table_id == id) {
            *table_id = tbl->dp_table_id;
        }
    }

    return id == *table_id;
}

static int
translate_action_id(struct dp_prog *prog, uint32_t *action_id)
{
    struct dpif_action_id *act;
    uint32_t id = *action_id;

    HMAP_FOR_EACH_WITH_HASH (act, hmap_node, hash_int(id, 0),
                             &prog->action_ids) {
        if (act->action_id == id) {
            *action_id = act->dp_action_id;
        }
    }

    return id == *action_id;
}

static uint32_t
get_p4info_action_id(struct dp_prog *prog, uint32_t action_id)
{
    struct dpif_action_id *act;

    HMAP_FOR_EACH (act, hmap_node, &prog->action_ids) {
        if (act->dp_action_id == action_id) {
            return act->action_id;
        }
    }

    return 0;
}

static const char*
replace_char(const char* str, char find, char replace){
    char *current_pos = strchr(str,find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos,find);
    }
    return str;
}

/* ## ----------------------------------------- ## */
/* ## Functions implementing packet processing. ## */
/* ## ----------------------------------------- ## */

static inline struct dp_netdev_action_flow *
dp_netdev_action_flow_init(struct dp_netdev_pmd_thread *pmd,
                           uint16_t action_type,
                           void *actions_args,
                           uint32_t hash)
{
    struct dp_netdev_action_flow *act_flow = xmalloc(sizeof *act_flow);
    struct nlattr *act = NULL;
    switch (action_type) {
        case REDIRECT: {
            uint32_t port = *((uint32_t *)actions_args);
            act = xzalloc(NLA_HDRLEN + sizeof(port));
            act->nla_len = NLA_HDRLEN + sizeof(port);
            act->nla_type = OVS_ACTION_ATTR_OUTPUT;
            nullable_memcpy(act + 1, &port, sizeof(port));
            break;
        }
        case ABORT:
        case DROP: {
            act = xzalloc(NLA_HDRLEN);
            act->nla_len = NLA_HDRLEN;
            act->nla_type = OVS_ACTION_ATTR_DROP;
            break;
        }
    }
    act_flow->action = act;
    act_flow->action_batch = NULL; // force batch initialization
    act_flow->hash = hash;

    cmap_insert(&pmd->action_table, &act_flow->node, hash);

    return act_flow;
}

static inline struct dp_netdev_action_flow *
get_dp_netdev_action_flow(struct dp_netdev_pmd_thread *pmd,
                          uint32_t hash)
{
    const struct cmap_node *node;

    node = cmap_find(&pmd->action_table, hash);
    if (OVS_LIKELY(node != NULL)) {
        return CONTAINER_OF(node, struct dp_netdev_action_flow, node);
    }
    return NULL;
}

static inline void
packet_batch_per_action_init(struct packet_batch_per_action *batch,
                             struct dp_netdev_action_flow *action)
{
    action->action_batch = batch;
    batch->action = action;

    dp_packet_batch_init(&batch->output_batch);
}

static inline void
packet_batch_per_action_update(struct packet_batch_per_action *batch,
                               struct dp_packet *pkt)
{
    dp_packet_batch_add(&batch->output_batch, pkt);
}

static inline void
dp_netdev_queue_action_batches(struct dp_packet *pkt,
                               struct dp_netdev_action_flow *action)
{
    struct packet_batch_per_action *batch = action->action_batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = xmalloc(sizeof(struct packet_batch_per_action));
        packet_batch_per_action_init(batch, action);
    }

    packet_batch_per_action_update(batch, pkt);
}

static inline void
packet_batch_per_action_execute(struct packet_batch_per_action *batch,
                                struct dp_netdev_pmd_thread *pmd)
{
    struct nlattr *act = batch->action->action;

    if (OVS_UNLIKELY(!act)) {
        return;
    }

    dp_netdev_execute_actions(pmd, &batch->output_batch, false, NULL,
                              act, act->nla_len);
    dp_packet_batch_init(&batch->output_batch);
}

static struct dp_prog *
get_dp_prog(struct dp_ubpf *dp, odp_port_t in_port)
{
    struct dp_prog *prog;
    const struct cmap_node *node;

    uint32_t hash = hash_int(odp_to_u32(in_port), 0);
    node = cmap_find(&dp->dp_progs_port_map, hash);
    if (!node) {
        return NULL;
    }

    prog = CONTAINER_OF(node, struct dp_prog, cmap_node);

    return prog;
}

static inline void
protocol_independent_processing(struct dp_netdev_pmd_thread *pmd,
                                struct dp_packet_batch *packets_,
                                odp_port_t in_port)
{
    struct dp_ubpf *dp = dp_ubpf_cast(pmd->dp);

    struct dp_prog *prog = get_dp_prog(dp, in_port);
    if (OVS_LIKELY(prog)) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {

            struct standard_metadata std_meta = {
                    .input_port = odp_to_u32(in_port),
                    .output_action = ABORT,  /* ABORT packet by default. */
                    .output_port = 0,
            };

            ubpf_handle_packet(prog->vm, &std_meta, packet);

            /* To simplify we hash two words (output_action, output_port) regardless of the action. */
            uint32_t hash = hash_2words(std_meta.output_action,
                                        std_meta.output_port);
            struct dp_netdev_action_flow *act_flow;
            act_flow = get_dp_netdev_action_flow(pmd, hash);
            if (OVS_UNLIKELY(!act_flow)) {
                act_flow = dp_netdev_action_flow_init(pmd,
                      std_meta.output_action, &std_meta.output_port, hash);
            }
            dp_netdev_queue_action_batches(packet, act_flow);
        }

        struct dp_netdev_action_flow *output_flow;
        CMAP_FOR_EACH(output_flow, node, &pmd->action_table) {
            packet_batch_per_action_execute(output_flow->action_batch, pmd);
        }

    }

}

static void
process_ubpf(struct dp_netdev_pmd_thread *pmd,
             struct dp_packet_batch *packets,
             bool md_is_valid OVS_UNUSED, odp_port_t port_no)
{
    protocol_independent_processing(pmd, packets, port_no);
}


/* ## -------------------------------------------- ## */
/* ## Functions implementing dpif_class interface. ## */
/* ## -------------------------------------------- ## */

static int
dpif_ubpf_init(void)
{
    /* Some uBPF specific objects may be initialized here. */

    /* initialize dpif-netdev too. */
    dpif_netdev_init();
    return 0;
}

static struct dpif *
create_dpif_ubpf(struct dp_ubpf *dp)
{
    struct dpif_ubpf *dpif;

    struct dpif *dpifp = create_dpif_netdev(&dp->dp_netdev);
    dpif = xrealloc(dpifp, sizeof(struct dpif_ubpf));
    dpif->dp = dp;

    return &dpif->dpif_netdev.dpif;
}

static int
create_dp_ubpf(const char *name, const struct dpif_class *class,
               struct dp_ubpf **dpp)
{
    struct dp_ubpf *dp;

    dp = xzalloc(sizeof *dp);

    int error = construct_dp_netdev(name, class, &dp->dp_netdev);
    if (error) {
        VLOG_INFO("Error creating dp netdev");
        return error;
    }

    dp->dp_netdev.process_cb = process_ubpf;

    shash_add(&dp_ubpfs, name, dp);

    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    cmap_init(&dp->dp_progs_port_map);

    *dpp = dp;
    return 0;
}

static int
dpif_ubpf_open(const struct dpif_class *class,
               const char *name, bool create, struct dpif **dpifp)
{
    int error;
    struct dp_ubpf *dp;

    ovs_mutex_lock(&dp_ubpf_mutex);
    dp = shash_find_data(&dp_ubpfs, name);
    if (!dp) {
        error = create ? create_dp_ubpf(name, class, &dp) : ENODEV;
    } else {
        error = (dp->dp_netdev.class != class ? EINVAL
                                              : create ? EEXIST
                                                       : 0);
    }
    if (!error) {
        *dpifp = create_dpif_ubpf(dp);
    }
    ovs_mutex_unlock(&dp_ubpf_mutex);
    return error;
}

static void
dpif_ubpf_close(struct dpif *dpif)
{
    struct dpif_ubpf *dpif_ubpf = dpif_ubpf_cast(dpif);
    struct dp_ubpf *dp = dpif_ubpf->dp;

    ovs_mutex_lock(&dp_prog_mutex);
    cmap_destroy(&dp->dp_progs_port_map);
    ovs_mutex_unlock(&dp_prog_mutex);
    shash_find_and_delete(&dp_ubpfs, dp->name);
    free(CONST_CAST(char *, dp->name));

    dpif_netdev_close(&dpif_ubpf->dpif_netdev.dpif);
}

static int
dpif_ubpf_set_config(struct dpif *dpif OVS_UNUSED, const struct smap *other_config OVS_UNUSED)
{
    /* TODO: Set uBPF-specific and netdev configuration. */
    return 0;
}

/*
 * If configuration parameter exists this function updates its value.
 * If configuration parameter does not exist it sets the configuration of a given port.
 */
static int
dpif_ubpf_port_set_config(struct dpif *dpif, odp_port_t port_no,
                          const struct smap *cfg)
{
    struct dp_ubpf *dp_ubpf = dpif_ubpf_cast(dpif)->dp;
    int prog_no = smap_get_int(cfg, "program", -1);

    VLOG_INFO("Setting prog %d for port %d", prog_no, port_no);

    ovs_mutex_lock(&dp_prog_mutex);
    struct dp_prog *prog = dp_progs[prog_no];
    cmap_insert(&dp_ubpf->dp_progs_port_map, &prog->cmap_node,
                hash_int(odp_to_u32(port_no), 0));
    ovs_mutex_unlock(&dp_prog_mutex);
    return 0;
}

static int
dp_prog_set_mappings(struct dp_prog *prog, const pi_p4info_t *p4info)
{
    struct ubpf_vm *vm = prog->vm;

    for (pi_p4_id_t id = pi_p4info_table_begin(p4info);
         id != pi_p4info_table_end(p4info);
         id = pi_p4info_table_next(p4info, id)) {
        VLOG_INFO("Table ID %u", id);

        const char *tbl_name = pi_p4info_table_name_from_id(p4info, id);

        /* Convert name provided by P4Info to adjust it to uBPF's naming convention. */
        const char *tbl = replace_char(tbl_name, '.', '_');

        struct ubpf_map *map = ubpf_lookup_registered_map(vm, tbl);
        struct dpif_table_id *tbl_id = xzalloc(sizeof *tbl_id);
        tbl_id->table_id = id;
        tbl_id->dp_table_id = map->id;
        hmap_insert(&prog->table_ids, &tbl_id->hmap_node, hash_int(id, 0));
        VLOG_INFO("Table '%s' ID mapping inserted %u <-> %d", tbl, id, map->id);

        size_t num_actions;
        int act_id = 0;
        const pi_p4_id_t *actions = pi_p4info_table_get_actions(p4info, id, &num_actions);
        for (int i = 0; i < num_actions; i++) {
            pi_p4_id_t action = actions[i];
            struct dpif_action_id *action_id = xzalloc(sizeof *action_id);
            /* The order of Actions in uBPF program is the same as the order of actions in P4 program. */
            action_id->action_id = action;
            action_id->dp_action_id = act_id;
            hmap_insert(&prog->action_ids, &action_id->hmap_node, hash_int(action, 0));
            VLOG_INFO("Action ID mapping inserted %u <-> %d", action, act_id);
            act_id++;
        }
    }

    return 0;
}

static int
dp_prog_set(struct dpif *dpif OVS_UNUSED, struct dpif_prog prog)
{
    struct dp_prog *dp_prog;

    ovs_mutex_lock(&dp_prog_mutex);
    dp_prog = dp_progs[prog.id];

    if (dp_prog) {
        /* P4 program with a given ID exists. */
        ovs_mutex_unlock(&dp_prog_mutex);
        return EEXIST;
    }

    struct ubpf_vm *vm = create_ubpf_vm((OVS_FORCE const ovs_be16) prog.id);
    if (!load_bpf_prog(vm, prog.data_len, prog.data)) {
        ubpf_destroy(vm);
        ovs_mutex_unlock(&dp_prog_mutex);
        return -1; /* FIXME: not sure what to return. */
    }

    dp_prog = xzalloc(sizeof *dp_prog);
    dp_prog->id = prog.id;
    dp_prog->vm = vm;
    dp_prog->p4info = prog.p4info;
    hmap_init(&dp_prog->table_ids);
    hmap_init(&dp_prog->action_ids);
    dp_prog->default_action_set = false;

    dp_progs[prog.id] = dp_prog;
    ovs_mutex_unlock(&dp_prog_mutex);

    dp_prog_set_mappings(dp_prog, prog.p4info);

    return 0;
}

static void
dp_prog_destroy_(struct dp_prog *prog)
{
    if (prog) {
        ubpf_destroy(prog->vm);
        free(prog);
    }
}

static void
dp_prog_unset(struct dpif *dpif OVS_UNUSED, uint32_t prog_id)
{
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return;
    }

    ovs_mutex_lock(&dp_prog_mutex);
    struct dpif_table_id *table_id, *next;
    HMAP_FOR_EACH_SAFE (table_id, next, hmap_node, &prog->table_ids) {
        free(table_id);
    }
    hmap_destroy(&prog->table_ids);

    struct dpif_action_id *action_id, *next_act;
    HMAP_FOR_EACH_SAFE (action_id, next_act, hmap_node, &prog->action_ids) {
        free(action_id);
    }
    hmap_destroy(&prog->action_ids);
    dp_prog_destroy_(prog);
    dp_progs[prog_id] = NULL;
    ovs_mutex_unlock(&dp_prog_mutex);
}

static bool
isLPM(const pi_p4info_t *p4info, uint32_t table_id)
{
    size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
    for (size_t i = 0; i < num_match_fields; i++) {
        const pi_p4info_match_field_info_t *finfo =
                pi_p4info_table_match_field_info(p4info, table_id, i);
        if (finfo->match_type == PI_P4INFO_MATCH_TYPE_LPM) {
            return true;
        }
    }
    return false;
}

/*
 * TODO: prepare description
 */
static char *
build_key(const pi_p4info_t *p4info, uint32_t table_id, struct ubpf_map *map, const char *match_key)
{
    bool lpm_type = isLPM(p4info, table_id);
    size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);

    size_t buf_size = !lpm_type ? map->key_size : map->key_size + (4 * num_match_fields);
    char *key = xzalloc(buf_size);
    char *key_ptr = key;
    memset(key, 0, buf_size);
    for (int i = 0; i < num_match_fields; i++) {
        const pi_p4info_match_field_info_t *finfo =
                pi_p4info_table_match_field_info(p4info, table_id, i);
        size_t key_size = (finfo->bitwidth + 7) / 8;
        size_t bpf_key_size = ROUND_UP(key_size, 4);
        if (lpm_type) {
            uint32_t prefix_len = 32;
            if (finfo->match_type == PI_P4INFO_MATCH_TYPE_LPM) {
                /* TODO: verify if endianness is correct. */
                memcpy(&prefix_len, match_key+key_size, 4);
            }
            memcpy(key_ptr, &prefix_len, 4);
            key_ptr += 4;

            int offset = bpf_key_size - key_size;
            int k_idx = bpf_key_size - 1 - offset;
            for (int k = 0; k < key_size; k++) {
                key_ptr[k_idx] = match_key[k];
                k_idx--;
            }
            key_ptr += bpf_key_size;
            match_key += key_size + 4;
        } else {
            /* If not LPM type, construct a simple key. */
            /* Fill the key with data from `match_key`.
             * According to PI documentation match_key is provided in a network-byte order.
             * so that we need to reverse the byte array. */
            int offset = bpf_key_size - key_size;
            int k_idx = bpf_key_size - 1 - offset;
            for (int k = 0; k < key_size; k++) {
                key_ptr[k_idx] = match_key[k];
                k_idx--;
            }

            match_key += key_size;
        }
    }

    return key;
}

/* The structure of map value should be as follows:
 * ACTION_ID (4 bytes) [ACTION_DATA]
 * The total width of map value equals the width of the largest possible map value.
 * The total width is stored in `map->value_size'.
 * */
static uint8_t *
construct_map_value(struct dp_prog *prog, struct ubpf_map *map, uint32_t action_id, const char *action_data, size_t data_size)
{
    const pi_p4info_t *p4info = prog->p4info;
    uint8_t *value = xzalloc(map->value_size);
    memset(value, 0, map->value_size);

    if (data_size > 0) {
        int v_idx = 4; /* First 4 bytes are allocated for "action_id". */
        size_t num_params;
        const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, action_id,
                                                                  &num_params);
        for (size_t i = 0; i < num_params; i++) {
            pi_p4_id_t p_id = param_ids[i];
            size_t p_bw = pi_p4info_action_param_bitwidth(p4info, action_id, p_id);
            size_t nbytes = (p_bw + 7) / 8;

            /* Fill the value with data from `action_data`.
             * uBPF requires to have value data in reversed order.
             * */
            for (int k = 0; k < nbytes; k++) {
                value[k + v_idx] = (uint8_t) (action_data[nbytes - k - 1]);
            }

            v_idx += nbytes;
            action_data += nbytes;
        }
    }

    translate_action_id(prog, &action_id);
    memcpy(value, &action_id, sizeof(uint32_t));

    return value;
}



static int
dp_table_entry_add(struct dpif *dpif OVS_UNUSED, uint32_t prog_id,
                   uint32_t table_id,
                   uint32_t action_id,
                   const char *match_key, size_t key_size OVS_UNUSED,
                   const char *action_data, size_t data_size)
{
    int error;
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return EEXIST;
    }

    uint32_t p4info_table_id = table_id;
    error = translate_table_id(prog, &table_id);
    if (error) {
        VLOG_WARN("Datapath cannot translate table ID.");
        return EEXIST;
    }

    struct ubpf_vm *vm = prog->vm;

    struct ubpf_map *map = vm->ext_maps[table_id];
    if (!map) {
        VLOG_WARN("Table %d does not exist.", table_id);
        return EEXIST;
    }

    void *key = (void *) build_key(prog->p4info, p4info_table_id, map, match_key);
    void *value = (void *) construct_map_value(prog, map, action_id, action_data, data_size);
    error = ubpf_map_update(map, key, value);
    if (error) {
        VLOG_WARN("ubpf: the update_map() operation failed (status=%d).", error);
        /* FIXME: not sure what to return. */
        error = -1;
        goto out;
    }

out:
    free(key);
    free(value);

    return error;
}

static int
dp_table_entry_set_default(struct dpif *dpif OVS_UNUSED, uint32_t prog_id,
                           uint32_t table_id,
                           uint32_t action_id,
                           const char *action_data, size_t data_size)
{
    int error;
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return EEXIST;
    }

    error = translate_table_id(prog, &table_id);
    if (error) {
        VLOG_WARN("Datapath cannot translate table ID.");
        return EEXIST;
    }

    /* The default action map's identifier */
    uint32_t default_table_id = table_id + 1;
    struct ubpf_vm *vm = prog->vm;
    struct ubpf_map *map = vm->ext_maps[default_table_id];

    if (!map) {
        VLOG_WARN("BPF map %d does not exist.", default_table_id);
        return EEXIST;
    }

    uint32_t zero_key = 0;
    void *value = (void *) construct_map_value(prog, map, action_id, action_data, data_size);
    error = ubpf_map_update(map, &zero_key, value);

    if (error) {
        VLOG_WARN("ubpf: the update_map() operation failed (status=%d).", error);
        /* FIXME: not sure what to return. */
        error = -1;
        goto out;
    }

out:
    prog->default_action_set = true;
    free(value);
    return error;
}

/*
 * As we retrieve data from uBPF VM in a network byte-order, we need to convert it to host byte-order.
 * If map->key_size is greater than 'key_size' defined in P4 program 'offset' is used to copy only the
 * 'key_size' number of bytes.
 */
static char *
alloc_and_swap(char *data, size_t size, int offset)
{
    char *buf = xzalloc(size);
    for (int i=0; i<size; i++) {
        buf[i] = data[size-offset-1-i];
    }
    return buf;
}

static int
dp_table_entry_get_default(struct dpif *dpif OVS_UNUSED, uint32_t prog_id,
                           uint32_t table_id, uint32_t *action_id, char **action_data)
{
    int error;
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return EEXIST;
    }

    if (!prog->default_action_set) {
        /* Return empty action. */
        return 0;
    }

    error = translate_table_id(prog, &table_id);
    if (error) {
        VLOG_WARN("Datapath cannot translate table ID.");
        return EEXIST;
    }

    uint32_t default_table_id = table_id + 1;
    struct ubpf_vm *vm = prog->vm;
    struct ubpf_map *map = vm->ext_maps[default_table_id];

    if (!map) {
        VLOG_WARN("BPF map %d does not exist.", default_table_id);
        return EEXIST;
    }

    uint32_t zero_key = 0;
    void *value = ubpf_map_lookup(map, &zero_key);

    uint32_t *bpf_act_id = (uint32_t *) value;
    *action_id = get_p4info_action_id(prog, *bpf_act_id);
    char *datap = ((char* ) value + sizeof *action_id);
    *action_data = alloc_and_swap(datap, map->value_size - sizeof *action_id, 0);

    return 0;
}


static int
dp_table_query(struct dpif *dpif OVS_UNUSED, uint32_t prog_id,
               uint32_t table_id,
               struct ovs_list *entries)
{
    int error;
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return EEXIST;
    }

    uint32_t p4info_table_id = table_id;
    error = translate_table_id(prog, &table_id);
    if (error) {
        VLOG_WARN("Datapath cannot translate table ID.");
        return EEXIST;
    }

    struct ubpf_vm *vm = prog->vm;

    struct ubpf_map *map = vm->ext_maps[table_id];
    if (!map) {
        VLOG_WARN("Table %d does not exist.", table_id);
        return EEXIST;
    }

    unsigned int data_size = ubpf_map_size(map) * (map->key_size + map->value_size);
    char *data = xzalloc(data_size);
    char *datap = data;
    int nr_entries = ubpf_map_dump(map, data);

    for (int i = 0; i < nr_entries; i++) {
        struct p4rtutil_table_entry *entry = xmalloc(sizeof *entry);

        char *key = alloc_and_swap(datap, map->key_size, map->key_size - pi_p4info_table_match_key_size(prog->p4info, p4info_table_id));
        datap = datap + map->key_size;

        // TODO: do we need to allocate new memory for action_id?
        uint32_t *action_id = (uint32_t *) alloc_and_swap(datap, sizeof(uint32_t), 0);
        datap = datap + sizeof(*action_id);

        char *action_data = alloc_and_swap(datap, map->value_size - sizeof *action_id, 0);
        datap = datap + (map->value_size - sizeof *action_id);

        entry->handle_id = 0; /* don't define any */
        entry->priority = 0; /* set 0 by default */
        entry->match_key = key;
        entry->table_id = p4info_table_id;
        entry->action_id = get_p4info_action_id(prog, *action_id);
        entry->action_data = action_data;

        ovs_list_push_back(entries, &entry->list_node);
        free(action_id);
    }

    free(data);

    return 0;
}

static int
dp_table_entry_del(struct dpif *dpif OVS_UNUSED, uint32_t prog_id,
                   uint32_t table_id,
                   const char *match_key,
                   size_t key_size OVS_UNUSED)
{
    int error = 0;
    struct dp_prog *prog;

    ovs_mutex_lock(&dp_prog_mutex);
    prog = dp_progs[prog_id];
    ovs_mutex_unlock(&dp_prog_mutex);

    if (!prog) {
        /* uBPF program is not installed. */
        return EEXIST;
    }

    uint32_t p4info_table_id = table_id;
    error = translate_table_id(prog, &table_id);
    if (error) {
        VLOG_ERR("Datapath cannot translate table ID.");
        return EEXIST;
    }

    struct ubpf_vm *vm = prog->vm;

    struct ubpf_map *map = vm->ext_maps[table_id];
    if (!map) {
        VLOG_ERR("Table %d does not exist.", table_id);
        return EEXIST;
    }

    void *key = (void *) build_key(prog->p4info, p4info_table_id, map, match_key);
    error = ubpf_map_delete(map, key);
    free(key);
    if (error) {
        VLOG_ERR("ubpf: the delete_map() operation failed (status=%d).", error);
        /* FIXME: not sure what to return. */
        return -1;
    }

    return 0;
}

const struct dpif_class dpif_ubpf_class = {
        "ubpf",
        true,
        dpif_ubpf_init,
        dpif_netdev_enumerate,
        dpif_netdev_port_open_type,
        dpif_ubpf_open,
        dpif_ubpf_close,
        dpif_netdev_destroy,
        dpif_netdev_run,
        dpif_netdev_wait,
        dpif_netdev_get_stats,
        NULL,                      /* set_features */
        dpif_netdev_port_add,
        dpif_netdev_port_del,
        dpif_ubpf_port_set_config,
        dpif_netdev_port_query_by_number,
        dpif_netdev_port_query_by_name,
        NULL,                       /* port_get_pid */
        dpif_netdev_port_dump_start,
        dpif_netdev_port_dump_next,
        dpif_netdev_port_dump_done,
        dpif_netdev_port_poll,
        dpif_netdev_port_poll_wait,
        NULL,                       /* flow_flush */
        NULL,                       /* flow_dump_create */
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,                       /* operate */
        NULL,                       /* recv_set */
        NULL,                       /* handlers_set */
        dpif_ubpf_set_config,
        NULL,
        NULL,                       /* recv */
        NULL,                       /* recv_wait */
        NULL,                       /* recv_purge */
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,                       /* ct_set_timeout_policy */
        NULL,                       /* ct_get_timeout_policy */
        NULL,                       /* ct_del_timeout_policy */
        NULL,                       /* ct_timeout_policy_dump_start */
        NULL,                       /* ct_timeout_policy_dump_next */
        NULL,                       /* ct_timeout_policy_dump_done */
        NULL,                       /* ct_get_timeout_policy_name */
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        dp_prog_set,
        dp_prog_unset,
        dp_table_entry_add,
        dp_table_entry_set_default,
        dp_table_entry_get_default,
        dp_table_query,
        dp_table_entry_del,
};
