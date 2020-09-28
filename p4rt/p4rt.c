#include <config.h>
#include <errno.h>
#include <string.h>
#include <PI/proto/pi_server.h>
#include <PI/p4info.h>

#include <PI/int/pi_int.h>
#include <PI/pi.h>
#include <PI/target/pi_imp.h>
#include <PI/target/pi_tables_imp.h>

#include "netdev.h"
#include "p4rt.h"
#include "p4rt-provider.h"

#include "openvswitch/hmap.h"
#include "hash.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "smap.h"
#include "sset.h"
#include "lib/dpif.h"
#include "lib/p4rt-objects.h"

VLOG_DEFINE_THIS_MODULE(p4rt);

/* ## ------------------------------------- ## */
/* ## Global (shared) objects used by p4rt. ## */
/* ## ------------------------------------- ## */

/* Map from datapath name to struct p4rt, for use by unixctl commands. */
static struct hmap all_p4rts = HMAP_INITIALIZER(&all_p4rts);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* All registered p4rt classes, in probe order. */
static const struct p4rt_class **p4rt_classes;
static size_t n_p4rt_classes;
static size_t allocated_p4rt_classes;

/* Global lock that protects all flow table operations. */
struct ovs_mutex p4rt_mutex = OVS_MUTEX_INITIALIZER;

/* ## ------------------------- ## */
/* ## Prototypes for functions. ## */
/* ## ------------------------- ## */

struct p4port *p4rt_get_port(const struct p4rt *p4rt, ofp_port_t port_no);
int p4rt_class_register(const struct p4rt_class *new_class);
static void p4port_destroy(struct p4port *, bool del);
static void p4rt_destroy__(struct p4rt *p);

/* ## --------------------------------------- ## */
/* ## Private functions used locally by p4rt. ## */
/* ## --------------------------------------- ## */

static struct p4rt *
p4rt_lookup_by_dev_id(uint64_t dev_id)
{
    struct p4rt *p4rt;

    HMAP_FOR_EACH (p4rt, hmap_node, &all_p4rts) {
        if (p4rt->dev_id == dev_id) {
            return p4rt;
        }
    }
    return NULL;
}

static const struct p4rt_class *
p4rt_class_find__(const char *type)
{
    size_t i;

    for (i = 0; i < n_p4rt_classes; i++) {
        const struct p4rt_class *class = p4rt_classes[i];
        struct sset types;
        bool found;

        sset_init(&types);
        class->enumerate_types(&types);
        found = sset_contains(&types, type);
        sset_destroy(&types);

        if (found) {
            return class;
        }
    }
    VLOG_WARN("unknown datapath type %s", type);
    return NULL;
}

/* Registers a new p4rt class.  After successful registration, new p4rts
 * of that type can be created using p4rt_create(). */
int
p4rt_class_register(const struct p4rt_class *new_class)
{
    size_t i;

    for (i = 0; i < n_p4rt_classes; i++) {
        if (p4rt_classes[i] == new_class) {
            return EEXIST;
        }
    }

    if (n_p4rt_classes >= allocated_p4rt_classes) {
        p4rt_classes = x2nrealloc(p4rt_classes,
                                  &allocated_p4rt_classes, sizeof *p4rt_classes);
    }
    p4rt_classes[n_p4rt_classes++] = new_class;
    return 0;
}

static void
p4rt_port_destroy(struct p4rt_port *port)
{
    free(port->name);
    free(port->type);
}

static void
p4rt_destroy_defer__(struct p4rt *p)
    OVS_EXCLUDED(p4rt_mutex)
{
        ovsrcu_postpone(p4rt_destroy__, p);
}

static void
p4rt_destroy__(struct p4rt *p)
    OVS_EXCLUDED(p4rt_mutex)
{
    ovs_mutex_lock(&p4rt_mutex);
    hmap_remove(&all_p4rts, &p->hmap_node);
    ovs_mutex_unlock(&p4rt_mutex);

    free(p->name);
    free(p->type);
    hmap_destroy(&p->ports);

    p->p4rt_class->dealloc(p);
}

static void
p4rt_program_destroy(struct program *prog)
{
    if (prog) {
        prog->p4rt->p4rt_class->prog_del(prog);
        prog->p4rt->p4rt_class->prog_dealloc(prog);
    }
}

static int
p4rt_port_query_by_name(struct p4rt *p4rt, const char *name, struct p4rt_port *portp)
{
    int error;
    error = p4rt->p4rt_class->port_query_by_name(p4rt, name, portp);
    if (error) {
        memset(portp, 0, sizeof *portp);
    }
    return error;
}

static ofp_port_t
alloc_p4rt_port(struct p4rt *p4rt OVS_UNUSED, const char *netdev_name OVS_UNUSED)
{
    /* TODO: get next port number from the pool. */
    return u16_to_ofp(1);
}

static uint64_t
p4rt_assign_dev_id(uint64_t requested_dev_id)
{
    struct p4rt *p;

    p = p4rt_lookup_by_dev_id(requested_dev_id);
    if (!p && requested_dev_id < MAX_PROGS) {
        /* Requested device ID is free, we can use it. */
        return requested_dev_id;
    } else if (requested_dev_id != UINT64_MAX) {
        /* Default value is not provided.
         * It means user did provide ID, which is already taken.
         * We should fail in such case. */
        return UINT64_MAX;
    }

    uint64_t dev_id_to_use = 0, alloc_port_no = 0;

    /* Get the first dev_id, which is not used by any p4rt. */
    for (;;) {
        /* Start from the beginning if we reached MAX_PROGS. */
        if (alloc_port_no >= MAX_PROGS-1) {
            dev_id_to_use = UINT64_MAX;
            break;
        }

        p = p4rt_lookup_by_dev_id(alloc_port_no);
        if (!p) {
            dev_id_to_use = alloc_port_no;
            break;
        }
        alloc_port_no++;
    }

    return dev_id_to_use;
}

static int
p4rt_port_open(struct p4rt *p4rt OVS_UNUSED,
               struct p4rt_port *p4port,
               struct netdev **p_netdev)
{
    int error;
    struct netdev *netdev;

    *p_netdev = NULL;
    error = netdev_open(p4port->name, p4port->type, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: ignoring port %s (%"PRIu32") because netdev %s "
                                                         "cannot be opened (%s)",
                p4port->name,
                p4port->name, p4port->port_no,
                p4port->name, ovs_strerror(error));
        return 0;
    }

    if (p4port->port_no == OFPP_NONE) {
        if (!strcmp(p4rt->name, p4port->name)) {
            p4port->port_no = OFPP_LOCAL;
        } else {
            ofp_port_t port_no = alloc_p4rt_port(p4rt, p4port->name);
            if (port_no == OFPP_NONE) {
                VLOG_WARN_RL(&rl, "%s: failed to allocate port number "
                                  "for %s.", p4rt->name, p4port->name);
                netdev_close(netdev);
                return ENOSPC;
            }
            p4port->port_no = port_no;
        }
    }

    *p_netdev = netdev;
    return 0;
}

static void
p4port_destroy__(struct p4port *port)
{
    struct p4rt *p4rt = port->p4rt;

    hmap_remove(&p4rt->ports, &port->hmap_node);

    netdev_close(port->netdev);
    p4rt->p4rt_class->port_dealloc(port);
}

static void
p4port_destroy(struct p4port *port, bool del)
{
    if (port) {
        port->p4rt->p4rt_class->port_destruct(port, del);
        p4port_destroy__(port);
    }
}

static void
p4port_remove(struct p4port *p4port)
{
    p4port_destroy(p4port, true);
}

static struct p4port *
p4rt_get_port_by_name(const struct p4rt *p4rt, const char *name)
{
    struct p4port *port;

    HMAP_FOR_EACH (port, hmap_node, &p4rt->ports) {
        if (!strcmp(netdev_get_name(port->netdev), name)) {
            return port;
        }
    }

    return NULL;
}

static void
attach_port_to_prog(struct p4port *port, uint64_t prog_id)
{
    struct p4rt *p4rt = port->p4rt;
    if (!strcmp(netdev_get_name(port->netdev), p4rt->name)) {
        return;
    }

    struct smap cfg = SMAP_INITIALIZER(&cfg);
    smap_add_format(&cfg, "program", "%lu", prog_id);

    p4rt->p4rt_class->port_set_config(port, &cfg);
    smap_destroy(&cfg);
}

static int
p4port_install(struct p4rt *p4rt, struct netdev *netdev, ofp_port_t port_no)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct p4port *p4port;
    int error;

    /* Create p4port. */
    p4port = p4rt->p4rt_class->port_alloc();
    if (!p4port) {
        error = ENOMEM;
        goto error;
    }

    p4port->p4rt = p4rt;
    p4port->netdev = netdev;
    p4port->port_no = port_no;
    p4port->created = time_msec();

    /* Add port to 'p'. */
    hmap_insert(&p4rt->ports, &p4port->hmap_node,
                hash_ofp_port(p4port->port_no));

    /* Let the p4rt_class initialize its private data. */
    error = p4rt->p4rt_class->port_construct(p4port);
    if (error) {
        goto error;
    }

    if (p4rt->prog) {
        attach_port_to_prog(p4port, p4rt->dev_id);
    }

    return 0;

error:
    VLOG_INFO("%s: could not add port %s (%s)",
              p4rt->name, netdev_name, ovs_strerror(error));
    VLOG_WARN_RL(&rl, "%s: could not add port %s (%s)",
                 p4rt->name, netdev_name, ovs_strerror(error));
    if (p4port) {
        p4port_destroy__(p4port);
    } else {
        netdev_close(netdev);
    }
    return error;
}

static int
update_port(struct p4rt *p4rt, const char *name)
{
    struct p4rt_port p4rt_port;
    struct netdev *netdev;
    struct p4port *port;
    int error = 0;

    /* Fetch 'name''s location and properties from the datapath. */
    if (p4rt_port_query_by_name(p4rt, name, &p4rt_port)) {
        netdev = NULL;
    } else {
        error = p4rt_port_open(p4rt, &p4rt_port, &netdev);
    }

    if (netdev) {
        port = p4rt_get_port(p4rt, p4rt_port.port_no);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {

        } else {
            if (port) {
                p4port_remove(port);
            }
            error = p4port_install(p4rt, netdev, p4rt_port.port_no);
        }
    }

    p4rt_port_destroy(&p4rt_port);

    return error;
}

static void
p4rt_attach_ports_to_prog(struct p4rt *p4rt)
{
    struct p4port *port;
    HMAP_FOR_EACH (port, hmap_node, &p4rt->ports) {
        attach_port_to_prog(port, p4rt->dev_id);
    }
}

static int
p4rt_prog_install(struct p4rt *p4rt, const pi_p4info_t *p4info, const char *data, size_t data_len)
{
    int error = 0;
    struct program *prog = NULL;

    if (!p4rt->prog) {
        prog = p4rt->p4rt_class->program_alloc();
        if (!prog) {
            error = ENOMEM;
            goto error;
        }
    } else {
        prog = p4rt->prog;
    }

    *CONST_CAST(struct p4rt **, &prog->p4rt) = p4rt;
    prog->p4info = p4info;
    prog->data = data;
    prog->data_len = data_len;

    error = p4rt->p4rt_class->program_insert(prog);
    if (error) {
        goto error;
    }

    ovs_mutex_lock(&p4rt_mutex);
    p4rt->prog = prog;
    p4rt->p4info = p4info;
    ovs_mutex_unlock(&p4rt_mutex);

    p4rt_attach_ports_to_prog(p4rt);

    VLOG_INFO("Added P4 program as Device ID %lu for %s", p4rt->dev_id, p4rt->name);

    return 0;

error:
    VLOG_WARN_RL(&rl, "failed to initialize P4 datapath of %s (%s)",
                 p4rt->name,
                 error == EEXIST ? "Program with a given Device ID already exists"
                                 : ovs_strerror(error));
    if (!p4rt->prog && prog) {
        p4rt->p4rt_class->prog_dealloc(prog);
    }

    return error;
}

/* ## ------------------------------------- ## */
/* ## Functions exposed and used by bridge. ## */
/* ## ------------------------------------- ## */

int
p4rt_enumerate_names(const char *type, struct sset *names)
{
    const struct p4rt_class *class = p4rt_class_find__(type);
    return class ? class->enumerate_names(type, names) : EAFNOSUPPORT;
}

const char *
p4rt_port_open_type(const struct p4rt *p4rt, const char *port_type)
{
    return (p4rt->p4rt_class->port_open_type
            ? p4rt->p4rt_class->port_open_type(p4rt->type, port_type)
            : port_type);
}

/* Clears 'types' and enumerates all registered p4rt types into it.  The
 * caller must first initialize the sset. */
void
p4rt_enumerate_types(struct sset *types)
{
    size_t i;

    sset_clear(types);
    for (i = 0; i < n_p4rt_classes; i++) {
        p4rt_classes[i]->enumerate_types(types);
    }
}

void
p4rt_init(void)
{
    p4rt_class_register(&p4rt_dpif_class);
    size_t i;
    for (i = 0; i < n_p4rt_classes; i++) {
        p4rt_classes[i]->init();
    }

    /* FIXME: Workaround as we cannot call DeviceMgr::init().
     * Remove it once this issue: https://github.com/p4lang/PI/issues/512 will be solved. */
    pi_init(256, NULL);
    PIGrpcServerRun();
}

void
p4rt_deinit(void)
{
    PIGrpcServerShutdown();
    PIGrpcServerCleanup();
}

int
p4rt_run(struct p4rt *p4rt)
{
    int error;

    error = p4rt->p4rt_class->run(p4rt);
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: run failed (%s)", p4rt->name, ovs_strerror(error));
    }

    return error;
}

void
p4rt_wait(struct p4rt *p)
{
    p->p4rt_class->wait(p);
}

int
p4rt_create(const char *datapath_name, const char *datapath_type,
            uint64_t *requested_dev_id, struct p4rt **p4rtp)
    OVS_EXCLUDED(p4rt_mutex)
{
    const struct p4rt_class *class;
    int error;
    struct p4rt *p4rt;
    uint64_t dev_id;
    *p4rtp = NULL;

    datapath_type = dpif_normalize_type(datapath_type);
    class = p4rt_class_find__(datapath_type);
    if (!class) {
        VLOG_WARN("could not create datapath %s of unknown type %s",
                  datapath_name, datapath_type);
        return EAFNOSUPPORT;
    }

    dev_id = p4rt_assign_dev_id(*requested_dev_id);
    if (dev_id == UINT64_MAX) {
        VLOG_ERR("failed to allocate Device ID for %s",
                 datapath_name);
        return EBUSY;
    }
    *requested_dev_id = dev_id;

    p4rt = class->alloc();
    if (!p4rt) {
        VLOG_ERR("failed to allocate datapath %s of type %s",
                 datapath_name, datapath_type);
        return ENOMEM;
    }

    /* Initialize. */
    ovs_mutex_lock(&p4rt_mutex);
    memset(p4rt, 0, sizeof *p4rt);
    p4rt->p4rt_class = class;
    p4rt->name = xstrdup(datapath_name);

    p4rt->p4info = NULL;
    p4rt->dev_id = dev_id;
    p4rt->type = xstrdup(datapath_type);
    hmap_insert(&all_p4rts, &p4rt->hmap_node,
    hash_string(p4rt->name, 0));
    hmap_init(&p4rt->ports);
    ovs_mutex_unlock(&p4rt_mutex);

    error = p4rt->p4rt_class->construct(p4rt);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, ovs_strerror(error));
        p4rt_destroy__(p4rt);
        return error;
    }

    *p4rtp = p4rt;
    return error;
}

int
p4rt_initialize_datapath(struct p4rt *p, const char *config_path, const char *p4info_path)
{
    int error = 0;

    if (p->prog) {
        /* P4 datapath is already initialized with P4 program */
        return error;
    }

    FILE *stream = !strcmp(config_path, "-") ? stdin : fopen(config_path, "r");
    if (stream == NULL) {
        error = ENOENT;
        VLOG_WARN_RL(&rl, "failed to initialize P4 datapath of %s "
                          "with binary from file '%s' (%s)",
                     p->name, config_path, ovs_strerror(error));
        return error;
    }

    fseek(stream, 0L, SEEK_END);
    size_t length = ftell(stream);
    fseek(stream, 0L, SEEK_SET);

    char *program = xzalloc(length);
    if (fread(program, sizeof(char), length, stream) != length) {
        error = ferror(stream) ? errno : EOF;
        fclose(stream);
        free(program);
        return error;
    }
    fclose(stream);

    pi_p4info_t *p4info;
    error = pi_add_config_from_file(p4info_path, PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
    if (error) {
        VLOG_ERR("%s: failed to load P4Info from file. Make sure that you provided P4Info in the JSON format.", p->name);
        return EINVAL;
    }


    int status = PIGrpcServerPipelineConfigSet(p->dev_id, program, length, p4info);
    if (status != PI_STATUS_SUCCESS) {
        VLOG_ERR("%s: failed to initialize P4 datapath (PIGrpcServer returned error).", p->name);
        return -1;
    }

    return 0;
}

void
p4rt_destroy(struct p4rt *p, bool del)
{
    struct p4port *port, *next_port;

    if (!p) {
        return;
    }

    HMAP_FOR_EACH_SAFE (port, next_port, hmap_node, &p->ports) {
        p4port_destroy(port, del);
    }

    p4rt_program_destroy(p->prog);

    p->p4rt_class->destruct(p, del);

    /* Destroying rules is deferred, must have 'p4rt' around for them. */
    ovsrcu_postpone(p4rt_destroy_defer__, p);
}

int
p4rt_delete(const char *name, const char *type)
{
    const struct p4rt_class *class = p4rt_class_find__(type);
    return (!class ? EAFNOSUPPORT
            : !class->del ? EACCES
            : class->del(type, name));
}

int
p4rt_type_run(const char *datapath_type)
{
    const struct p4rt_class *class;
    int error;

    datapath_type = datapath_type && datapath_type[0] ? datapath_type : "system";
    class = p4rt_class_find__(datapath_type);

    error = class->type_run ? class->type_run(datapath_type) : 0;
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: type_run failed (%s)",
                    datapath_type, ovs_strerror(error));
    }

    return error;
}

void
p4rt_type_wait(const char *datapath_type)
{
    const struct p4rt_class *class;

    datapath_type = dpif_normalize_type(datapath_type);
    class = p4rt_class_find__(datapath_type);

    if (class->type_wait) {
        class->type_wait(datapath_type);
    }
}

void
p4rt_get_ports(struct p4rt *p, struct sset *p4rt_ports)
{
    struct p4port *port, *next;

    HMAP_FOR_EACH_SAFE (port, next, hmap_node, &p->ports) {
        sset_add(p4rt_ports, netdev_get_name(port->netdev));
    }
}

struct p4port *
p4rt_get_port(const struct p4rt *p4rt, ofp_port_t port_no)
{
    struct p4port *port;

    HMAP_FOR_EACH_IN_BUCKET (port, hmap_node, hash_ofp_port(port_no),
                             &p4rt->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }

    return NULL;
}

int
p4rt_port_add(struct p4rt *p, struct netdev *netdev, ofp_port_t *ofp_portp)
{
    ofp_port_t ofp_port = ofp_portp ? *ofp_portp : OFPP_NONE;
    int error;

    error = p->p4rt_class->port_add(p, netdev, ofp_to_u16(ofp_port));
    if (!error) {
        const char *netdev_name = netdev_get_name(netdev);
        error = update_port(p, netdev_name);
    }

    if (ofp_portp) {
        *ofp_portp = OFPP_NONE;
        if (!error) {
            struct p4rt_port p4rt_port;

            error = p4rt_port_query_by_name(p,
                                            netdev_get_name(netdev),
                                            &p4rt_port);

            if (!error) {
                *ofp_portp = p4rt_port.port_no;
                p4rt_port_destroy(&p4rt_port);
            }
        }
    }

    return error;
}

int
p4rt_port_del(struct p4rt *p, const char *name)
{
    struct p4port *p4port = p4rt_get_port_by_name(p, name);
    int error;

    if (!p4port) {
        return ENODEV;
    }

    error = p->p4rt_class->port_del(p, ofp_to_u16(p4port->port_no));

    if (!error && p4port) {
        /* 'name' is the netdev's name and update_port() is going to close the
         * netdev.  Just in case update_port() refers to 'name' after it
         * destroys 'p4port', make a copy of it around the update_port()
         * call. */
        char *devname = xstrdup(name);
        update_port(p, devname);
        free(devname);
    }

    return error;
}

int
p4rt_prog_del(struct p4rt *p)
{
    struct program *prog = p->prog;
    p4rt_program_destroy(prog);
    return 0;
}

/* ## ------------- ## */
/* ## PI functions. ## */
/* ## ------------- ## */


pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info OVS_UNUSED,
                              pi_assign_extra_t *extra OVS_UNUSED) {

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_id);

    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_NOT_ASSIGNED;
    }

    VLOG_INFO("P4 device %lu assigned.", dev_id);

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size) {
    int error;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    error = p4rt_prog_install(p4rt, p4info, device_data, device_data_size);
    if (error) {
        return PI_STATUS_INVALID_CONFIG_TYPE;
    }

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle OVS_UNUSED,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite OVS_UNUSED,
                                pi_entry_handle_t *entry_handle OVS_UNUSED) {
    int error;
    struct p4rtutil_table_entry entry;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_tgt.dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    entry.table_id = table_id;
    entry.action_id = table_entry->entry.action_data->action_id;
    entry.match_key = match_key->data;
    entry.key_size = match_key->data_size;
    entry.action_data = table_entry->entry.action_data->data;
    entry.data_size = table_entry->entry.action_data->data_size;

    error = p4rt->p4rt_class->entry_add(p4rt, &entry);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to insert P4 table entry to device %lu (%s)",
                     dev_tgt.dev_id, ovs_strerror(error));
        return PI_STATUS_TARGET_ERROR;
    }

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_set(pi_session_handle_t session_handle OVS_UNUSED,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
    int error;
    struct p4rtutil_table_entry entry;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_tgt.dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    entry.table_id = table_id;
    entry.action_id = table_entry->entry.action_data->action_id;
    entry.action_data = table_entry->entry.action_data->data;
    entry.data_size = table_entry->entry.action_data->data_size;
    entry.is_default = true;
    error = p4rt->p4rt_class->entry_add(p4rt, &entry);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to set default table entry for table '%s' of device %lu (%s)",
                     pi_p4info_table_name_from_id(p4rt->p4info, table_id),
                     dev_tgt.dev_id, ovs_strerror(error));
        return PI_STATUS_TARGET_ERROR;
    }

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_get(pi_session_handle_t session_handle OVS_UNUSED,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
    int error;
    uint32_t action_id = 0;
    char *action_data = NULL;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_tgt.dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    error = p4rt->p4rt_class->entry_get_default(p4rt, table_id, &action_id, &action_data);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to get default table entry for table '%s' of device %lu (%s)",
                     pi_p4info_table_name_from_id(p4rt->p4info, table_id),
                     dev_tgt.dev_id, ovs_strerror(error));
    }

    table_entry->entry_properties = NULL;
    table_entry->direct_res_config = NULL;
    if (action_id == 0) {
        table_entry->entry_type = PI_ACTION_ENTRY_TYPE_NONE;
        goto out;
    }

    table_entry->entry_type = PI_ACTION_ENTRY_TYPE_DATA;
    uint32_t adata_size = pi_p4info_action_data_size(p4rt->p4info, action_id);
    pi_action_data_t *adata = xzalloc(sizeof(pi_action_data_t) + adata_size);
    adata->p4info = p4rt->p4info;
    adata->action_id = action_id;
    adata->data_size = adata_size;
    adata->data = action_data;
    table_entry->entry.action_data = adata;

out:
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_reset(pi_session_handle_t session_handle OVS_UNUSED,
                                           pi_dev_tgt_t dev_tgt OVS_UNUSED,
                                           pi_p4_id_t table_id OVS_UNUSED) {
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_default_action_get_handle(
        pi_session_handle_t session_handle OVS_UNUSED, pi_dev_tgt_t dev_tgt OVS_UNUSED,
        pi_p4_id_t table_id OVS_UNUSED, pi_entry_handle_t *entry_handle OVS_UNUSED) {
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_default_action_done(pi_session_handle_t session_handle OVS_UNUSED,
                                          pi_table_entry_t *table_entry) {
    if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
        pi_action_data_t *action_data = table_entry->entry.action_data;
        if (action_data) {
            free(action_data);
        }
    }

    return PI_STATUS_SUCCESS;
}

static char *
emit_pi_table_entries(struct p4rt *p, pi_p4_id_t table_id, struct ovs_list *entries, size_t *entries_size)
{
    /* We make use of ofpbuf as buffer. */
    struct ofpbuf *buf = ofpbuf_new(32);

    struct p4rtutil_table_entry *entry, *next;
    LIST_FOR_EACH_SAFE (entry, next, list_node, entries) {

        ofpbuf_put(buf, &entry->handle_id, sizeof(uint64_t));
        ofpbuf_put(buf, &entry->priority, sizeof(uint32_t));
        size_t key_size = pi_p4info_table_match_key_size(p->p4info, table_id);
        ofpbuf_put(buf, entry->match_key, key_size);

        uint32_t type = PI_ACTION_ENTRY_TYPE_DATA;
        ofpbuf_put(buf, &type, sizeof(uint32_t));
        ofpbuf_put(buf, &entry->action_id, sizeof(uint32_t));

        uint32_t adata_size = pi_p4info_action_data_size(p->p4info, entry->action_id);
        ofpbuf_put(buf, &adata_size, sizeof(uint32_t));
        ofpbuf_put(buf, entry->action_data, adata_size);

        /* FIXME: properties. */
        uint32_t tmp = 0;
        ofpbuf_put(buf, &tmp, sizeof(uint32_t));
        ofpbuf_put(buf, &tmp, sizeof(uint32_t));

        free((void *) entry->match_key);
        free((void *) entry->action_data);
        free(entry);
    }

    *entries_size = buf->size;

    char *b = ofpbuf_steal_data(buf);
    ofpbuf_delete(buf);

    return b;
}

pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle OVS_UNUSED,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
    int error;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_tgt.dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    struct ovs_list *entries = xmalloc(sizeof *entries);
    ovs_list_init(entries);

    error = p4rt->p4rt_class->fetch_entries(p4rt, table_id, entries);
    if (error) {
        free(entries);
        VLOG_WARN_RL(&rl, "failed to fetch P4 table entries from device %lu (%s)",
                     dev_tgt.dev_id, ovs_strerror(error));
        return PI_STATUS_TARGET_ERROR;
    }

    res->num_entries = ovs_list_size(entries);
    res->p4info = p4rt->p4info;
    res->mkey_nbytes = pi_p4info_table_match_key_size(p4rt->p4info, table_id);

    size_t entries_size = 0;
    char *buf = emit_pi_table_entries(p4rt, table_id, entries, &entries_size);

    res->entries = buf;
    res->entries_size = entries_size;

    free(entries);
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle OVS_UNUSED,
                                         pi_table_fetch_res_t *res)
{
    free(res->entries);
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(pi_session_handle_t session_handle OVS_UNUSED,
                                   pi_dev_id_t dev_id OVS_UNUSED, pi_p4_id_t table_id OVS_UNUSED,
                                   pi_entry_handle_t entry_handle OVS_UNUSED)
{
    /* We do not support handle-based delete operation */
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_entry_delete_wkey(pi_session_handle_t session_handle OVS_UNUSED,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key) {
    int error;

    struct p4rt *p4rt = p4rt_lookup_by_dev_id(dev_tgt.dev_id);
    if (!p4rt) {
        /* P4 Device does not exist. */
        return PI_STATUS_DEV_OUT_OF_RANGE;
    }

    error = p4rt->p4rt_class->entry_del(p4rt, table_id, match_key->data, match_key->data_size);
    if (error) {
        VLOG_ERR("%s: failed to delete table entry from table with ID %u", p4rt->name, table_id);
        return PI_STATUS_TARGET_ERROR;
    }

    return PI_STATUS_SUCCESS;
}

/* ## ------------------------------- ## */
/* ## Functions exposed to ovs-p4ctl. ## */
/* ## ------------------------------- ## */

static struct p4rt *
p4rt_lookup(const char *name)
{
    struct p4rt *p4rt;

    HMAP_FOR_EACH_WITH_HASH (p4rt, hmap_node, hash_string(name, 0),
                             &all_p4rts) {
        if (!strcmp(p4rt->name, name)) {
            return p4rt;
        }
    }
    return NULL;
}

int
p4rt_query_switch_features(const char *name, struct p4rt_switch_features *features)
{
    struct p4rt *p4rt = p4rt_lookup(name);
    if (!p4rt) {
        return ENODEV;
    }

    features->n_tables = 0; /* TODO: query no of tables from datapath or save it while inserting new program */
    features->n_ports = hmap_count(&p4rt->ports);

    return 0;
}
