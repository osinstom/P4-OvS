#include <config.h>
#include <PI/target/pi_act_prof_imp.h>

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
    (void)session_handle;
    (void)dev_tgt;
    (void)act_prof_id;
    (void)action_data;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)mbr_handle;
    (void)action_data;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
    (void)session_handle;
    (void)dev_tgt;
    (void)act_prof_id;
    (void)max_size;
    (void)grp_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_set_mbrs(
        pi_session_handle_t session_handle, pi_dev_id_t dev_id,
        pi_p4_id_t act_prof_id, pi_indirect_handle_t grp_handle, size_t num_mbrs,
        const pi_indirect_handle_t *mbr_handles, const bool *activate) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)num_mbrs;
    (void)mbr_handles;
    (void)activate;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_activate_mbr(pi_session_handle_t session_handle,
                                          pi_dev_id_t dev_id,
                                          pi_p4_id_t act_prof_id,
                                          pi_indirect_handle_t grp_handle,
                                          pi_indirect_handle_t mbr_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_deactivate_mbr(pi_session_handle_t session_handle,
                                            pi_dev_id_t dev_id,
                                            pi_p4_id_t act_prof_id,
                                            pi_indirect_handle_t grp_handle,
                                            pi_indirect_handle_t mbr_handle) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)mbr_handle;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                       pi_dev_tgt_t dev_tgt,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
    (void)session_handle;
    (void)dev_tgt;
    (void)act_prof_id;
    (void)res;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle,
                                   pi_act_prof_fetch_res_t *res) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)mbr_handle;
    (void)res;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t grp_handle,
                                   pi_act_prof_fetch_res_t *res) {
    (void)session_handle;
    (void)dev_id;
    (void)act_prof_id;
    (void)grp_handle;
    (void)res;

    return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                            pi_act_prof_fetch_res_t *res) {
    (void)session_handle;
    (void)res;

    return PI_STATUS_SUCCESS;
}

int _pi_act_prof_api_support(pi_dev_id_t dev_id) {
    (void)dev_id;

    return PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS |
           PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR;
}

