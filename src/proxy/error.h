#ifndef BOOST_PROXY_ERROR
#define BOOST_PROXY_ERROR

#include <string>
#include <exception>
#include <system_error>


namespace cw {
namespace error {

enum class error_type {
    no_error = 0,
    exc_runtime_error,
    exc_exception,
    exc_process_error,
    command_error,
    command_not_found,
    invalid_password,
    conflict,
    conflict_user,
    invalid_uri,
    validation_error,
    bad_request,
    not_found,
    command_unsupported,
    batchsystem_invalid,
    error_code,
    writing_credentials_error,
    other,
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

