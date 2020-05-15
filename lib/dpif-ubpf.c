#include <config.h>
#include <errno.h>

#include "dpif-netdev.h"
#include "dpif-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/shash.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "bpf.h"

VLOG_DEFINE_THIS_MODULE(dpif_ubpf);

/* ## --------------------------------------- ## */
/* ## dpif-ubpf helper structures definition. ## */
/* ## --------------------------------------- ## */

struct dp_prog {
    uint16_t id;
    struct ubpf_vm *vm;
};

struct dp_ubpf {
    struct dp_netdev dp_netdev;
    const char *const name;

    /* Data plane program. */
    struct dp_prog *prog;
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

/* ## ------------------------------------------ ## */
/* ## Global (shared) objects used by dpif-ubpf. ## */
/* ## ------------------------------------------ ## */

/* Protects against changes to 'dp_ubpfs'. */
static struct ovs_mutex dp_ubpf_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_ubpfs OVS_GUARDED_BY(dp_ubpf_mutex)
        = SHASH_INITIALIZER(&dp_ubpfs);

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

/* ## ----------------------------------------- ## */
/* ## Functions implementing packet processing. ## */
/* ## ----------------------------------------- ## */

static inline struct dp_netdev_action_flow *
dp_netdev_action_flow_init(struct dp_netdev_pmd_thread *pmd,
                           uint16_t action_type,
                           void *actions_args,
                           uint32_t hash)
{
    struct dp_netdev_action_flow *act_flow = xmalloc(sizeof *act_flow);  // TODO: must be freed somewhere later
    struct nlattr *act;
    switch (action_type) {
        case REDIRECT: {
            uint32_t port = *((uint32_t *)actions_args);
            act = xzalloc(NLA_HDRLEN + sizeof(port));
            act->nla_len = NLA_HDRLEN + sizeof(port);
            act->nla_type = OVS_ACTION_ATTR_OUTPUT;
            nullable_memcpy(act + 1, &port, sizeof(port));
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
    struct cmap_node *node;
    struct dp_netdev_action_flow *act_flow;

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
    dp_netdev_execute_actions(pmd, &batch->output_batch, false, NULL,
                              act, NLA_HDRLEN + sizeof(uint32_t)); /* FIXME: this is really temporary. */
    dp_packet_batch_init(&batch->output_batch);
}

static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_int(odp_to_u32(port_no), 0), hmap) {
        if (tx->port->port_no == port_no) {
            return tx;
        }
    }

    return NULL;
}

static inline void
protocol_independent_processing(struct dp_netdev_pmd_thread *pmd,
                                struct dp_packet_batch *packets_,
                                odp_port_t in_port)
{
    struct dp_ubpf *dp = dp_ubpf_cast(pmd->dp);

    if (OVS_LIKELY(dp->prog)) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                struct tx_port *p;

                struct standard_metadata std_meta = {
                        .input_port = odp_to_u32(in_port),
                };

                ubpf_handle_packet(dp->prog->vm, &std_meta, packet);
                switch (std_meta.output_action) {
                    case REDIRECT: {
                        p = tx_port_lookup(&pmd->send_port_cache, u32_to_odp(std_meta.output_port));
                        dp_packet_batch_add(&p->output_pkts, packet);
                        if (OVS_LIKELY(p)) {
                            int error = netdev_send(p->port->netdev, pmd->static_tx_qid, &p->output_pkts, true);
                        }

                        /* TODO: output action batching. */
                        /* uint32_t hash = hash_2words(std_meta.output_action,
                                                    std_meta.output_port);

                        struct dp_netdev_action_flow *act_flow;
                        act_flow = get_dp_netdev_action_flow(pmd, hash);
                        if (OVS_UNLIKELY(!act_flow)) {
                            act_flow = dp_netdev_action_flow_init(pmd,
                                    REDIRECT, &std_meta.output_port, hash);
                        }
                        dp_netdev_queue_action_batches(packet, act_flow); */
                        break;
                    }
                }
            }

        /* TODO: output action batching. */
        /* struct dp_netdev_action_flow *output_flow;
        CMAP_FOR_EACH(output_flow, node, &pmd->action_table) {
            packet_batch_per_action_execute(output_flow->action_batch, pmd);
        } */

    }

}

static void
process_ubpf(struct dp_netdev_pmd_thread *pmd,
             struct dp_packet_batch *packets,
             bool md_is_valid, odp_port_t port_no)
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
    dp->prog = NULL;

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

    shash_find_and_delete(&dp_ubpfs, dp->name);
    free(CONST_CAST(char *, dp->name));

    dpif_netdev_close(&dpif_ubpf->dpif_netdev.dpif);
}

static int
dpif_ubpf_set_config(struct dpif *dpif, const struct smap *other_config)
{
    /* TODO: Set uBPF-specific and netdev configuration. */
    return 0;
}

static int
dpif_ubpf_port_set_config(struct dpif *dpif, odp_port_t port_no,
                          const struct smap *cfg)
{
    /* TODO: Set uBPF-specific and netdev configuration for ports. */
    return 0;
}

static int
dp_prog_set(struct dpif *dpif, struct dpif_prog prog)
{
    struct dp_ubpf *dp_ubpf = dpif_ubpf_cast(dpif)->dp;
    struct dp_prog *dp_prog;

    struct ubpf_vm *vm = create_ubpf_vm(prog.id);
    if (!load_bpf_prog(vm, prog.data_len, prog.data)) {
        ubpf_destroy(vm);
        return -1; /* FIXME: not sure what to return. */
    }

    dp_prog = xzalloc(sizeof *dp_prog);
    dp_prog->id = prog.id;
    dp_prog->vm = vm;

    if (dp_ubpf->prog) {
        free(dp_ubpf->prog);
        dp_ubpf->prog = NULL;
    }
    dp_ubpf->prog = dp_prog;

    return 0;
}

static void
dp_prog_destroy_(struct dp_prog *prog)
{
    ubpf_destroy(prog->vm);
    free(prog);
}

static void
dp_prog_unset(struct dpif *dpif, uint32_t prog_id)
{
    struct dp_ubpf *dp = dpif_ubpf_cast(dpif)->dp;

    if (!dp->prog) {
        /* uBPF program is not installed. */
        return;
    }

    dp_prog_destroy_(dp->prog);
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
};
