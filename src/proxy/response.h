#ifndef BOOST_PROXY_RESPONSE
#define BOOST_PROXY_RESPONSE

#include <boost/beast/http.hpp>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <string>

#include "batchsystem/json.h"

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

resp requestUnknown(const std::string& uri, boost::beast::http::verb method) {
    return json_error("BadRequest", "Unknown request: "+std::string(boost::beast::http::to_string(method))+" "+uri, boost::beast::http::status::bad_request);
}

resp validationError(const std::string& msg) {
    return json_error("ValidationError", msg, boost::beast::http::status::bad_request);
}

resp commandUnknown(const std::string& command) {
    return validationError("Unknown command: "+command);
}

resp commandSuccess() {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    r.first.AddMember("success", true, allocator);
    r.second = boost::beast::http::status::ok;
    return r;
}

resp commandReturn(std::error_code ec, const std::string& failType = "Running command failed", boost::beast::http::status statusFail=boost::beast::http::status::ok) {
    if (ec) {
        return json_error_ec(ec, failType);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = statusFail;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            data.AddMember("success", true, allocator);
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

template <typename T>
resp containerReturn(std::error_code ec, const std::vector<T>& entry) {
    if (ec) {
        return json_error_ec(ec);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.first.SetObject();

        rapidjson::Value entryArr;
        entryArr.SetArray();
        for (const auto& e : entry) {
            rapidjson::Document subdocument(&r.first.GetAllocator());
            cw::batch::json::serialize(e, subdocument);
            entryArr.PushBack(subdocument, allocator);
        }
        r.first.AddMember("data", entryArr, allocator);
        r.second = boost::beast::http::status::ok;
        return r;
    }
}

resp getBatchInfoReturn(std::error_code ec, const cw::batch::BatchInfo& batchinfo) {
    if (ec) {
        return json_error_ec(ec);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Document subdocument(&r.first.GetAllocator());
            cw::batch::json::serialize(batchinfo, subdocument);
            r.first.AddMember("data", subdocument, allocator);
        }
        return r;
    }
}

resp runJobReturn(std::error_code ec, const std::string& jobName) {
    if (ec) {
        return json_error_ec(ec);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            data.AddMember("job", jobName, allocator);
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

resp addUserReturn(std::error_code ec) {
    return commandReturn(ec, "Writing credentials failed", boost::beast::http::status::created);
}


}
}
}

#endif /* BOOST_PROXY_RESPONSE */
