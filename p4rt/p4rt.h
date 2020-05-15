#ifndef P4RT_H
#define P4RT_H 1

#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "netdev.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct p4rt;

/* Needed for the lock annotations. */
extern struct ovs_mutex p4rt_mutex;

/* A port within a P4Runtime switch.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct p4rt_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    ofp_port_t port_no;         /* Port number. We re-use OpenFlow port format. */
};

const char * p4rt_port_open_type(const struct p4rt *p4rt, const char *port_type);
int p4rt_run(struct p4rt *);
int p4rt_create(const char *datapath, const char *datapath_type, struct p4rt **p4rt);
int p4rt_port_add(struct p4rt *p, struct netdev *netdev, ofp_port_t *ofp_portp);

#ifdef  __cplusplus
}
#endif

#endif /* p4rt.h */