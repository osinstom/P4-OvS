#include <config.h>
#include <PI/target/pi_counter_imp.h>

pi_status_t _pi_counter_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index, int flags,
                             pi_counter_data_t *counter_data) {
    (void)session_handle;
    (void)dev_tgt;
    (void)counter_id;
    (void)index;
    (void)flags;
    (void)counter_data;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                              size_t index,
                              const pi_counter_data_t *counter_data) {
    (void)session_handle;
    (void)dev_tgt;
    (void)counter_id;
    (void)index;
    (void)counter_data;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_read_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle, int flags,
                                    pi_counter_data_t *counter_data) {
    (void)session_handle;
    (void)dev_tgt;
    (void)counter_id;
    (void)entry_handle;
    (void)flags;
    (void)counter_data;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_write_direct(pi_session_handle_t session_handle,
                                     pi_dev_tgt_t dev_tgt,
                                     pi_p4_id_t counter_id,
                                     pi_entry_handle_t entry_handle,
                                     const pi_counter_data_t *counter_data) {
    (void)session_handle;
    (void)dev_tgt;
    (void)counter_id;
    (void)entry_handle;
    (void)counter_data;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_hw_sync(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                PICounterHwSyncCb cb, void *cb_cookie) {
    (void)session_handle;
    (void)dev_tgt;
    (void)counter_id;
    (void)cb;
    (void)cb_cookie;

    return PI_STATUS_SUCCESS;
}
