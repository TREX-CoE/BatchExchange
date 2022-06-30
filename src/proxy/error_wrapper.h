#ifndef BOOST_PROXY_ERROR_WRAPPER
#define BOOST_PROXY_ERROR_WRAPPER

#include <string>
#include <exception>
#include <system_error>

namespace cw {
namespace error {

class error_wrapper {
private:
    std::error_code _code;
    std::error_code _base = std::error_code();
    std::string _msg = "";
    int _statuscode = -1;
public:
    error_wrapper(std::error_code code_=std::error_code()): _code(code_) {}
    error_wrapper& with_msg(std::string msg_) { _msg = std::move(msg_); return *this; }
    error_wrapper& with_status(int statuscode_) { _statuscode = statuscode_; return *this; }
    error_wrapper& with_base(std::error_code base_) { _base = base_; return *this; }
    operator bool() const { return !!_code; }
    int statuscode() const { return _statuscode; }
    std::error_code ec() const { return _code; }
    std::error_code base_ec() const { return _base; }
    const std::string& msg() const { return _msg; }
};

}
}

#endif /* BOOST_PROXY_ERROR_WRAPPER */

