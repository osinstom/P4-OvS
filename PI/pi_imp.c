#include <config.h>
#include <PI/int/pi_int.h>
#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <config.h>
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(pi_imp);

pi_status_t _pi_init(int *abi_version, void *extra) {
    *abi_version = PI_ABI_VERSION;
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id) {
    (void)dev_id;
    VLOG_INFO("Injecting config: %d", dev_id);
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(pi_dev_id_t dev_id) {
    (void)dev_id;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_destroy() {

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_init(pi_session_handle_t *session_handle) {
    *session_handle = 0;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle) {
    (void)session_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_begin(pi_session_handle_t session_handle) {
    (void)session_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
    (void)session_handle;
    (void)hw_sync;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
    (void)dev_id;
    (void)pkt;
    (void)size;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_port_status_get(pi_dev_id_t dev_id, pi_port_t port,
                                pi_port_status_t *status) {
    (void)dev_id;
    (void)port;
    *status = PI_PORT_STATUS_UP;

    return PI_STATUS_SUCCESS;
}