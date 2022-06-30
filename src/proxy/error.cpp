#include "proxy/error.h"

#include <string>
#include <exception>
#include <system_error>

namespace {

using namespace cw::error;

const char* to_cstr(error_type type) {
    switch (type) {
        case error_type::no_error: return "";
        case error_type::exc_runtime_error: return "error";
        case error_type::exc_exception: return "error";
        case error_type::exc_process_error: return "error";
        case error_type::command_error: return "error";
        case error_type::command_unsupported: return "command not supported by batchsystem";
        case error_type::command_not_found: return "error";
        case error_type::invalid_password_empty: return "invalid password, cannot be empty";
        case error_type::conflict: return "error";
        case error_type::conflict_user: return "user already exists";
        case error_type::batchsystem_unknown: return "invalid batchsystem selected, use one of: pbs | slurm | lsf";
        case error_type::batchsystem_not_given: return "batchsystem not specified";
        case error_type::invalid_uri: return "could not parse uri";
        case error_type::validation_error: return "error";
        case error_type::bad_request: return "error";
        case error_type::socket_command_not_given: return "command not given";
        case error_type::socket_command_unknown: return "command unknown";
        case error_type::user_invalid: return "username invalid";
        case error_type::password_invalid: return "password invalid";
        case error_type::user_not_found: return "user not found";
        case error_type::login_scope_missing: return "use does not have needed scope";
        case error_type::login_user_not_found: return "login user not found";
        case error_type::login_password_mismatch: return "login password incorrect";
        case error_type::login_auth_header_invalid: return "authorization header could not be parsed";
        case error_type::not_found: return "error";
        case error_type::batchsystem_invalid: return "error";
        case error_type::error_code: return "error";
        case error_type::writing_credentials_error: return "error";
        case error_type::other: return "error";
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
