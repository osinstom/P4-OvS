#include <config.h>
#include <PI/p4info.h>
#include <PI/pi.h>
#include <PI/target/pi_learn_imp.h>

pi_status_t _pi_learn_config_set(pi_session_handle_t session_handle,
                                 pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 const pi_learn_config_t *config) {
    (void)session_handle;
    (void)dev_id;
    (void)learn_id;
    (void)config;
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
    (void)session_handle;
    (void)dev_id;
    (void)learn_id;
    (void)msg_id;
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
    (void)msg;
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}
