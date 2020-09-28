#ifndef P4RT_PROVIDER_H
#define P4RT_PROVIDER_H 1

#include <PI/p4info.h>
#include "openvswitch/hmap.h"
#include "lib/p4rt-objects.h"

/* According to PI library 256 is the maximum number of P4 devices. */
#define MAX_PROGS 256

struct p4rt {
    struct hmap_node hmap_node; /* In global 'all_p4rts' hmap. */
    const struct p4rt_class *p4rt_class;

    char *type;                 /* Datapath type. */
    char *name;                 /* Datapath name. */

    const pi_p4info_t *p4info;        /* P4Info describing a P4 program. */
    uint64_t dev_id;            /* Device ID used by P4Runtime to identify bridge. */

    /* Datapath. */
    struct program *prog;

    struct hmap ports;          /* Contains "struct p4port"s. */
};

/* A P4 port within a "struct p4rt".
 *
 * The port's name is netdev_get_name(port->netdev). */
struct p4port {
    struct hmap_node hmap_node; /* In struct p4rt's "ports" hmap. */
    struct p4rt *p4rt;          /* The p4rt that contains this port. */
    struct netdev *netdev;
    ofp_port_t port_no;         /* P4Runtime port number. */
    long long int created;      /* Time created, in msec. */
};

/* A P4 program representation within a "struct p4rt".
 *
 * It stores a target-specific binary compiled from a P4 program. */
struct program {
    struct p4rt *const p4rt;

    const pi_p4info_t *p4info;        /* P4Info describing a P4 program. */
    const char *data;               /* Target-specific representation of P4 program */
    size_t data_len;
};

/* P4Runtime provider interface.
 * This interface takes the best from OpenFlow provider. */
struct p4rt_class {
/* ## ----------------- ## */
/* ## Factory Functions ## */
/* ## ----------------- ## */

    /* Initializes provider. */
    void (*init)(void);

    /* Returns the type to pass to netdev_open() when a datapath of type
     * 'datapath_type' has a port of type 'port_type', for a few special
     * cases when a netdev type differs from a port type.  For example,
     * when using the userspace datapath, a port of type "internal"
     * needs to be opened as "tap".
     *
     * Returns either 'type' itself or a string literal, which must not
     * be freed. */
    const char *(*port_open_type)(const char *datapath_type,
                                  const char *port_type);

    /* Enumerates the types of all supported p4rt types into 'types'.  The
     * caller has already initialized 'types'.  The implementation should add
     * its own types to 'types' but not remove any existing ones, because other
     * p4rt classes might already have added names to it. */
    void (*enumerate_types)(struct sset *types);

    /* Enumerates the names of all existing datapath of the specified 'type'
     * into 'names' 'all_dps'.  The caller has already initialized 'names' as
     * an empty sset.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*enumerate_names)(const char *type, struct sset *names);

    /* Deletes the datapath with the specified 'type' and 'name'.  The caller
     * should have closed any open p4rt with this 'type' and 'name'; this
     * function is allowed to fail if that is not the case.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     * 'name' is one of the names enumerated by ->enumerate_names() for 'type'.
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*del)(const char *type, const char *name);

/* ## ------------------------ ## */
/* ## Top-Level type Functions ## */
/* ## ------------------------ ## */

    /* Performs any periodic activity required on p4rts of type
     * 'type'.
     *
     * An p4rt provider may implement it or not, depending on whether
     * it needs type-level maintenance.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*type_run)(const char *type);

    void (*type_wait)(const char *type);

/* ## --------------------------- ## */
/* ## Top-Level p4rt Functions ## */
/* ## --------------------------- ## */

    /*
     * CONSTRUCTION.
     */
    struct p4rt *(*alloc)(void);
    int (*construct)(struct p4rt *p4rt);
    void (*destruct)(struct p4rt *p4rt, bool del);
    void (*dealloc)(struct p4rt *p4rt);

    int (*run)(struct p4rt *p4rt);

    void (*wait)(struct p4rt *p4rt);

/* ## ---------------- ## */
/* ## p4port Functions ## */
/* ## ---------------- ## */

    struct p4port *(*port_alloc)(void);
    int (*port_construct)(struct p4port *p4port);
    void (*port_destruct)(struct p4port *p4port, bool del);
    void (*port_dealloc)(struct p4port *p4port);

    /* Looks up a port named 'devname' in 'p4rt'.  On success, returns 0 and
     * initializes '*port' appropriately. Otherwise, returns a positive errno
     * value.
     *
     * The caller owns the data in 'port' and must free it with
     * p4rt_port_destroy() when it is no longer needed. */
    int (*port_query_by_name)(const struct p4rt *p4rt,
                              const char *devname, struct p4rt_port *port);

    /* Attempts to add 'netdev' as a port with number `port_no' on 'p4rt'.
     * Returns 0 if successful, otherwise a positive errno value.
     * The caller should inform the implementation of the port through the
     * ->port_construct() method.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_add)(struct p4rt *p, struct netdev *netdev, uint16_t port_no);

    /* Refreshes datapath configuration of 'port'.
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*port_set_config)(const struct p4port *port, const struct smap *cfg);

    /* Deletes port number 'port_no' from the datapath for 'p4rt'.  Returns
     * 0 if successful, otherwise a positive errno value. */
    int (*port_del)(struct p4rt *p4rt, uint16_t port_no);

/* ## --------------------- ## */
/* ## Reconfigurable (P4) datapath Functions ## */
/* ## --------------------- ## */

    /* Life-cycle functions for a "struct program". */
    struct program *(*program_alloc)(void);
    int (*program_insert)(struct program *prog);
    void (*prog_del)(struct program *prog);
    void (*prog_dealloc)(struct program *prog);

/* ## ------------------------ ## */
/* ## P4 Table Entry functions ## */
/* ## ------------------------ ## */

    int (*entry_add)(struct p4rt *p, struct p4rtutil_table_entry *entry);
    int (*entry_del)(struct p4rt *p, uint32_t table_id, const char *match_key, size_t key_size);
    int (*fetch_entries)(struct p4rt *p, uint32_t table_id, struct ovs_list *entries);
    int (*entry_get_default)(struct p4rt *p, uint32_t table_id, uint32_t *action_id, char **action_data);
};

extern const struct p4rt_class p4rt_dpif_class;

#endif /* p4rt-provider.h */