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
        case error_type::command_not_found: return "error";
        case error_type::invalid_password: return "error";
        case error_type::conflict: return "error";
        case error_type::conflict_user: return "error";
        case error_type::invalid_uri: return "error";
        case error_type::validation_error: return "error";
        case error_type::bad_request: return "error";
        case error_type::not_found: return "error";
        case error_type::command_unsupported: return "error";
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
