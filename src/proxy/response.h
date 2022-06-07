#ifndef BOOST_PROXY_RESPONSE
#define BOOST_PROXY_RESPONSE

#include <boost/beast/http.hpp>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <string>

namespace cw {
namespace proxy {
namespace response {

using resp = std::pair<rapidjson::Document, boost::beast::http::status>;

resp json_error(const std::string& type, const std::string& message, boost::beast::http::status status) {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    {
        rapidjson::Value error;
        error.SetObject();
        error.AddMember("type", type, allocator);
        error.AddMember("message", message, allocator);
        error.AddMember("code", static_cast<int>(status), allocator);
        r.first.AddMember("error", error, allocator);
    }
    r.second = status;
    return r;
}

resp bad_request() {
    return json_error("Bad request", "Unsupported API call", boost::beast::http::status::bad_request);
}

resp json_error_ec(std::error_code ec, const std::string& type = "Running command failed") {
    return json_error(type, ec.message(), boost::beast::http::status::internal_server_error);
}

resp json_error_exc(const std::exception& e, const std::string& type = "Exception thrown") {
    return json_error(type, e.what(), boost::beast::http::status::internal_server_error);
}
resp json_error_exc(const cw::helper::ValidationError& e, const std::string& type = "Request body validation failed") {
    return json_error(type, e.what(), boost::beast::http::status::bad_request);
}

resp invalid_auth(const std::string& scope="") {
    return json_error("Invalid credentials or scope", "Could not authenticate user or user does not have requested scope(s)" + (scope.empty() ? "" : (": " + scope)), boost::beast::http::status::unauthorized);
}

resp invalid_login() {
    return json_error("Invalid login", "Could not authenticate user for login", boost::beast::http::status::unauthorized);
}

resp command_status(bool success) {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    r.first.AddMember("success", success, allocator);
    r.second = boost::beast::http::status::ok;
    return r;
}

}
}
}

#endif /* BOOST_PROXY_RESPONSE */
