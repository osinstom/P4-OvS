/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_H
#define DPIF_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cmap.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private.h"
#include "dpif-provider.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "fat-rwlock.h"
#include "ovs-thread.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

struct pmd_auto_lb {
    bool auto_lb_requested;     /* Auto load balancing requested by user. */
    bool is_enabled;            /* Current status of Auto load balancing. */
    uint64_t rebalance_intvl;
    uint64_t rebalance_poll_timer;
};

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET)
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

struct emc_entry {
    struct dp_netdev_flow *flow;
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];
};

/* Signature match cache, differentiate from EMC cache */
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};

struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
    /* EMC insertion probability context for the current processing cycle. */
    uint32_t emc_insert_min;
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache;

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* Action-Table
     *
     */
    struct ovs_mutex action_mutex;
    struct cmap action_table OVS_GUARDED;

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    struct seq *reload_seq;
    uint64_t last_reload_seq;

    /* These are atomic variables used as a synchronization and configuration
     * points for thread reload/exit.
     *
     * 'reload' atomic is the main one and it's used as a memory
     * synchronization point for all other knobs and data.
     *
     * For a thread that requests PMD reload:
     *
     *   * All changes that should be visible to the PMD thread must be made
     *     before setting the 'reload'.  These changes could use any memory
     *     ordering model including 'relaxed'.
     *   * Setting the 'reload' atomic should occur in the same thread where
     *     all other PMD configuration options updated.
     *   * Setting the 'reload' atomic should be done with 'release' memory
     *     ordering model or stricter.  This will guarantee that all previous
     *     changes (including non-atomic and 'relaxed') will be visible to
     *     the PMD thread.
     *   * To check that reload is done, thread should poll the 'reload' atomic
     *     to become 'false'.  Polling should be done with 'acquire' memory
     *     ordering model or stricter.  This ensures that PMD thread completed
     *     the reload process.
     *
     * For the PMD thread:
     *
     *   * PMD thread should read 'reload' atomic with 'acquire' memory
     *     ordering model or stricter.  This will guarantee that all changes
     *     made before setting the 'reload' in the requesting thread will be
     *     visible to the PMD thread.
     *   * All other configuration data could be read with any memory
     *     ordering model (including non-atomic and 'relaxed') but *only after*
     *     reading the 'reload' atomic set to 'true'.
     *   * When the PMD reload done, PMD should (optionally) set all the below
     *     knobs except the 'reload' to their default ('false') values and
     *     (mandatory), as the last step, set the 'reload' to 'false' using
     *     'release' memory ordering model or stricter.  This will inform the
     *     requesting thread that PMD has completed a reload cycle.
     */
    atomic_bool reload;             /* Do we need to reload ports? */
    atomic_bool wait_for_reload;    /* Can we busy wait for the next reload? */
    atomic_bool reload_tx_qid;      /* Do we need to reload static_tx_qid? */
    atomic_bool exit;               /* For terminating the pmd thread. */

    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;

    struct ovs_mutex bond_mutex;    /* Protects updates of 'tx_bonds'. */
    /* Map of 'tx_bond's used for transmission.  Written by the main thread
     * and read by the pmd thread. */
    struct cmap tx_bonds;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* Stats from previous iteration used by automatic pmd
     * load balance logic. */
    uint64_t prev_stats[PMD_N_STATS];
    atomic_count pmd_overloaded;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;

    /* Next time when PMD should try RCU quiescing. */
    long long next_rcu_quiesce;
};

typedef void process_packet_cb(struct dp_netdev_pmd_thread *pmd,
                               struct dp_packet_batch *packets,
                               bool md_is_valid, odp_port_t port_no);

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_mutex
 *    bond_mutex
 *    non_pmd_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS];
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;
    struct ovs_mutex tx_qid_pool_mutex;
    /* Use measured cycles for rxq to pmd assignment. */
    bool pmd_rxq_assign_cyc;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;

    uint64_t last_tnl_conf_seq;

    struct conntrack *conntrack;
    struct pmd_auto_lb pmd_alb;

    /* Bonds. */
    struct ovs_mutex bond_mutex; /* Protects updates of 'tx_bonds'. */
    struct cmap tx_bonds; /* Contains 'struct tx_bond'. */

    process_packet_cb *process_cb;  /* Callback function for processing packets. */
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
};

struct dp_netdev_port_state {
    struct hmap_position position;
    char *name;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */
struct tx_port {
    struct dp_netdev_port *port;
    int qid;
    long long last_used;
    struct hmap_node node;
    long long flush_time;
    struct dp_packet_batch output_pkts;
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];
};

/* Contained by struct tx_bond 'slave_buckets'. */
struct slave_entry {
    odp_port_t slave_id;
    atomic_ullong n_packets;
    atomic_ullong n_bytes;
};

/* Contained by struct dp_netdev_pmd_thread's 'tx_bonds'. */
struct tx_bond {
    struct cmap_node node;
    uint32_t bond_id;
    struct slave_entry slave_buckets[BOND_BUCKETS];
};

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

int dpif_netdev_init(void);
int dpif_netdev_enumerate(struct sset *all_dps,
                          const struct dpif_class *dpif_class);
const char *dpif_netdev_port_open_type(const struct dpif_class *class,
                                       const char *type);
void dpif_netdev_close(struct dpif *dpif);
int dpif_netdev_destroy(struct dpif *dpif);
bool dpif_netdev_run(struct dpif *dpif);
void dpif_netdev_wait(struct dpif *dpif);
int dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats);
int dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                         odp_port_t *port_nop);
int dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no);
int dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port);
int dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port);
int dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep);
int dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                               struct dpif_port *dpif_port);
int dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_);
int dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED);
void dpif_netdev_port_poll_wait(const struct dpif *dpif_);

struct dpif *create_dpif_netdev(struct dp_netdev *dp);
int construct_dp_netdev(const char *name, const struct dpif_class *class,
                        struct dp_netdev *dp);
void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet_batch *packets,
                          bool should_steal, const struct flow *flow,
                          const struct nlattr *actions, size_t actions_len);


#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
