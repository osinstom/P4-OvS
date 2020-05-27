#include <config.h>
#include <PI/target/pi_clone_imp.h>

pi_status_t _pi_clone_session_set(
        pi_session_handle_t session_handle, pi_dev_tgt_t dev_tgt,
        pi_clone_session_id_t clone_session_id,
        const pi_clone_session_config_t *clone_session_config) {
    (void)session_handle;
    (void)dev_tgt;
    (void)clone_session_id;
    (void)clone_session_config;
    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_clone_session_reset(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_clone_session_id_t clone_session_id) {
    (void)session_handle;
    (void)dev_tgt;
    (void)clone_session_id;

    return PI_STATUS_SUCCESS;
}
