#include "proxy/error.h"

#include <string>
#include <exception>
#include <system_error>

namespace {

using namespace cw::error;

const char* to_cstr(error_type type) {
    switch (type) {
        case error_type::exc_process_error: return "error";
        case error_type::command_error: return "error";
        case error_type::command_unsupported: return "command not supported by batchsystem";
        case error_type::command_not_found: return "error";
        case error_type::invalid_password_empty: return "invalid password, cannot be empty";
        case error_type::conflict_user: return "user already exists";
        case error_type::batchsystem_missing: return "batchsystem is not given";
        case error_type::batchsystem_not_string: return "batchsystem is not a string";
        case error_type::batchsystem_unknown: return "invalid batchsystem selected, use one of: pbs, slurm, lsf";
        case error_type::invalid_uri: return "could not parse uri";
        case error_type::request_unknown: return "request is unknown";
        case error_type::socket_command_not_string: return "command is not a string";
        case error_type::socket_command_missing: return "command is not given";
        case error_type::socket_command_unknown: return "command is unknown";
        case error_type::password_missing: return "password is not given";
        case error_type::password_not_string: return "password is not a string";
        case error_type::user_not_found: return "user not found";
        case error_type::tag_not_string: return "tag is not a string";
        case error_type::force_not_bool: return "force is not a bool";
        case error_type::node_state_unknown: return "invalid node state selected, use one of: resume, drain, undrain";
        case error_type::queue_state_unknown: return "invalid queue state selected, use one of: open, closed, inactive, draining";
        case error_type::user_missing: return "user is not given";
        case error_type::force_unknown: return "force invalid boolean like string";
        case error_type::user_not_string: return "user is not a string";
        case error_type::body_not_json: return "body is not json";
        case error_type::body_not_object: return "body is not an object";
        case error_type::scopes_not_array: return "scopes is not an array";
        case error_type::scope_invalid: return "scope is invalid, has to be a non empty string";
        case error_type::login_scope_missing: return "use does not have needed scope";
        case error_type::login_user_not_found: return "login user not found";
        case error_type::login_password_mismatch: return "login password incorrect";
        case error_type::login_auth_header_invalid: return "authorization header could not be parsed";
        case error_type::writing_credentials_error: return "error";
        case error_type::job_path_missing: return "error";
        case error_type::job_path_not_string: return "error";
        case error_type::job_nodes_not_int: return "error";
        case error_type::job_nodes_smaller_1: return "error";
        case error_type::job_nodesMax_not_int: return "error";
        case error_type::job_nodesMax_smaller_1: return "error";
        case error_type::job_tasks_not_int: return "error";
        case error_type::job_tasks_smaller_1: return "error";
        case error_type::job_gpus_not_int: return "error";
        case error_type::job_gpus_smaller_1: return "error";
        case error_type::job_missing: return "error";
        case error_type::job_not_string: return "error";
        case error_type::node_missing: return "error";
        case error_type::node_not_string: return "error";
        case error_type::queue_missing: return "error";
        case error_type::state_missing: return "error";
        case error_type::state_not_string: return "error";
        case error_type::queue_not_string: return "error";
        case error_type::rest_path_not_including_job_id: return "error";
        case error_type::rest_query_user_missing: return "error";
        case error_type::rest_path_not_including_node_id: return "error";
        case error_type::reason_not_string: return "error";
        case error_type::append_not_bool: return "error";
        case error_type::rest_path_not_including_queue_id: return "error";
        case error_type::comment_missing: return "error";
        case error_type::comment_not_string: return "error";
        case error_type::filterJobs_not_array: return "error";
        case error_type::filterJobs_not_string_array: return "error";
        case error_type::filterNodes_not_array: return "error";
        case error_type::filterNodes_not_string_array: return "error";
        default: return "(unrecognized error)";
    }
}


struct TrexErrCategory : std::error_category
{
  const char* name() const noexcept override;
  std::string message(int ev) const override;
};
 
const char* TrexErrCategory::name() const noexcept {
  return "trex";
}
 
std::string TrexErrCategory::message(int ev) const {
  return to_cstr(static_cast<error_type>(ev));
}
 
const TrexErrCategory error_cat {};

}

namespace cw {
namespace error {

const std::error_category& trex_category() noexcept {
    return error_cat;
}

std::error_code make_error_code(error_type e) {
  return {static_cast<int>(e), error_cat};
}

}
}
