#include <config.h>
#include <PI/target/pi_meter_imp.h>

pi_status_t _pi_meter_read(pi_session_handle_t session_handle,
                           pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                           size_t index, pi_meter_spec_t *meter_spec) {
    (void)session_handle;
    (void)dev_tgt;
    (void)meter_id;
    (void)index;
    (void)meter_spec;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_set(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, const pi_meter_spec_t *meter_spec) {
    (void)session_handle;
    (void)dev_tgt;
    (void)meter_id;
    (void)index;
    (void)meter_spec;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_read_direct(pi_session_handle_t session_handle,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                  pi_entry_handle_t entry_handle,
                                  pi_meter_spec_t *meter_spec) {
    (void)session_handle;
    (void)dev_tgt;
    (void)meter_id;
    (void)entry_handle;
    (void)meter_spec;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_set_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 const pi_meter_spec_t *meter_spec) {
    (void)session_handle;
    (void)dev_tgt;
    (void)meter_id;
    (void)entry_handle;
    (void)meter_spec;

    return PI_STATUS_SUCCESS;
}
