#ifndef P4RT_DPIF_H
#define P4RT_DPIF_H 1

#include "lib/dpif-provider.h"
#include "lib/uuid.h"
#include "ovs-thread.h"
#include "p4rt-provider.h"

/* All datapaths of a given type share a single dpif backer instance. */
struct p4rt_dpif_backer {
    char *type;
    struct dpif *dpif;

    struct ovs_rwlock odp_to_p4port_lock;
    struct hmap odp_to_p4port_map OVS_GUARDED;  /* Contains "struct p4port"s. */
};

struct p4rt_dpif {
    struct p4rt up;
    struct p4rt_dpif_backer *backer;

    /* Unique identifier for this instantiation of this bridge in this running
     * process.  */
    struct uuid uuid;

};

#endif /* p4rt-dpif.h */