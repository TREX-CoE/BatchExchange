#ifndef BOOST_PROXY_ERROR
#define BOOST_PROXY_ERROR

#include <string>
#include <exception>
#include <system_error>


namespace cw {
namespace error {

enum class error_type {
    unhandled_exception = 1,
    boost_process_error,
    command_error,
    command_not_found,
    invalid_password_empty,
    batchsystem_missing,
    batchsystem_not_string,
    batchsystem_unknown,
    conflict_user,
    invalid_uri,
    force_not_bool,
    login_scope_missing,
    password_missing,
    password_not_string,
    node_state_unknown,
    queue_state_unknown,
    force_unknown,
    user_not_found,
    tag_not_string,
    user_missing,
    user_not_string,
    scopes_not_array,
    scope_invalid,
    body_not_json,
    body_not_object,
    request_unknown,
    login_user_not_found,
    login_password_mismatch,
    login_auth_header_invalid,
    socket_command_missing,
    socket_command_not_string,
    socket_command_unknown,
    command_unsupported,
    writing_credentials_error,
    job_path_missing,
    job_path_not_string,
    job_nodes_not_int,
    job_nodes_smaller_1,
    job_nodesMax_not_int,
    job_nodesMax_smaller_1,
    job_tasks_not_int,
    job_tasks_smaller_1,
    job_gpus_not_int,
    job_gpus_smaller_1,
    job_missing,
    job_not_string,
    node_missing,
    node_not_string,
    queue_missing,
    state_missing,
    state_not_string,
    queue_not_string,
    rest_path_not_including_job_id,
    rest_query_user_missing,
    rest_path_not_including_node_id,
    reason_not_string,
    append_not_bool,
    rest_path_not_including_queue_id,
    comment_missing,
    comment_not_string,
    filterJobs_not_array,
    filterJobs_not_string_array,
    filterNodes_not_array,
    filterNodes_not_string_array,
    filterQueues_not_array,
    filterQueues_not_string_array,
    xcat_host_missing,
    xcat_port_missing,
    xcat_user_missing,
    xcat_password_missing,
    xcat_token_missing,
    xcat_auth_missing,
    xcat_osimage_missing,
    xcat_filter_missing,
    xcat_order_missing,
    xcat_action_missing,
    xcat_attributes_missing,
    invalid_method,
};

const std::error_category& trex_category() noexcept;

std::error_code make_error_code(error_type e);

}
}

namespace std
{
  template <>
  struct is_error_code_enum<cw::error::error_type> : true_type {};
}

#endif /* BOOST_PROXY_ERROR */
