#ifndef P4RT_H
#define P4RT_H 1

#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "netdev.h"
#include "p4rt-switch.h"

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

void p4rt_init(void);
void p4rt_deinit(void);
int p4rt_initialize_datapath(struct p4rt *p, const char *config_path, const char *p4info_path);

int p4rt_enumerate_names(const char *type, struct sset *names);
void p4rt_enumerate_types(struct sset *types);
const char * p4rt_port_open_type(const struct p4rt *p4rt, const char *port_type);
int p4rt_run(struct p4rt *);
int p4rt_type_run(const char *datapath_type);
void p4rt_type_wait(const char *datapath_type);
int p4rt_create(const char *datapath, const char *datapath_type,
                uint64_t requested_dev_id, struct p4rt **p4rt);
int p4rt_run(struct p4rt *);
void p4rt_wait(struct p4rt *p);
void p4rt_destroy(struct p4rt *p, bool del);
int p4rt_delete(const char *name, const char *type);
int p4rt_port_add(struct p4rt *p, struct netdev *netdev, ofp_port_t *ofp_portp);
int p4rt_port_del(struct p4rt *p, const char *name);
void p4rt_get_ports(struct p4rt *p, struct sset *p4rt_ports);
int p4rt_prog_del(struct p4rt *p);

/* unixctl commands */
int p4rt_query_switch_features(const char *name, struct p4rt_switch_features *features);

#ifdef  __cplusplus
}
#endif

#endif /* p4rt.h */
