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
    invalid_password,
    conflict,
    conflict_user,
    invalid_uri,
    validation_error,
    bad_request,
    not_found,
    command_unsupported,
    batchsystem_invalid,
}

struct error_wrapper {
    error_type type;
    std::string what;
    std::error_code code;
    int statuscode;
    error_wrapper(error_type type_, std::string what_, std::error_code code_=boost::system::error_code(), int status_code_=0): type(type_), what(what_), code(code_), statuscode(status_code_) {}
    error_wrapper(): error_wrapper(error_type::no_error, "") {}
    operator bool() const {
        return type == error_type::no_error;
    }
    int status_code() const {
        if (statuscode != 0) return statuscode;
        switch (type) {
            case error_type::not_found: return 404;
            default: return 500;
        }
    }
};

}
}

#endif /* BOOST_PROXY_ERROR */

