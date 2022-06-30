#ifndef BOOST_PROXY_RESPONSE
#define BOOST_PROXY_RESPONSE

#include <boost/beast/http.hpp>
#include <boost/optional.hpp>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <string>
#include <iostream>
#include <system_error>

#include "batchsystem/json.h"
#include "proxy/build_data.h"
#include "proxy/error.h"
#include "proxy/error_wrapper.h"

namespace {

using namespace cw::error;

int to_statuscode(const std::error_code& e) {
    if (e.category() == trex_category()) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
        switch (static_cast<error_type>(e.value())) {
            case error_type::bad_request: return 400;
            case error_type::socket_command_not_given: return 400;
            case error_type::invalid_password_empty: return 400;
            case error_type::invalid_uri: return 400;
            case error_type::batchsystem_not_given: return 400;
            case error_type::batchsystem_unknown: return 400;
            case error_type::user_invalid: return 400;
            case error_type::login_user_not_found: return 401;
            case error_type::login_password_mismatch: return 401;
            case error_type::login_auth_header_invalid: return 401;
            case error_type::login_scope_missing: return 401;
            case error_type::conflict_user: return 409;
            case error_type::user_not_found: return 404;
            default: return -1;
        }
#pragma GCC diagnostic pop
    }
    return -1;
}

}

namespace cw {
namespace proxy {
namespace response {

using namespace cw::error;

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

resp json_error(error_wrapper e) {
    resp r;
    int status = e.statuscode() == -1 ? to_statuscode(e.ec()) : e.statuscode();
    if (status == -1) status = 500;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    {
        rapidjson::Value error;
        error.SetObject();
        error.AddMember("type", e.ec().message(), allocator);
        if (!e.msg().empty()) error.AddMember("message", std::move(e).msg(), allocator);
        error.AddMember("code", e.ec().value(), allocator);
        error.AddMember("category", std::string(e.ec().category().name()), allocator);
        error.AddMember("status_code", status, allocator);
        if (e.base_ec()) {
            rapidjson::Value cause;
            cause.SetObject();
            cause.AddMember("type", e.ec().message(), allocator);
            cause.AddMember("code", e.ec().value(), allocator);
            cause.AddMember("category", std::string(e.ec().category().name()), allocator);
            error.AddMember("cause", cause, allocator);
        }
        r.first.AddMember("error", error, allocator);
    }
    r.second = boost::beast::http::status(status);
    return r;
}

resp json_error_ec(std::error_code ec, const std::string& type = "Running command failed") {
    return json_error(type, ec.message(), boost::beast::http::status::internal_server_error);
}

resp json_error_exc(const std::exception& e, const std::string& type = "Exception thrown") {
    return json_error(type, e.what(), boost::beast::http::status::internal_server_error);
}

resp requestUnknown(const std::string& uri, boost::beast::http::verb method) {
    return json_error("BadRequest", "Unknown request: "+std::string(boost::beast::http::to_string(method))+" "+uri, boost::beast::http::status::bad_request);
}

resp validationError(const std::string& msg) {
    return json_error("ValidationError", msg, boost::beast::http::status::bad_request);
}

resp notfoundError(const std::string& msg) {
    return json_error("NotFound", msg, boost::beast::http::status::not_found);
}

resp commandSuccess() {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    r.first.AddMember("success", true, allocator);
    r.second = boost::beast::http::status::ok;
    return r;
}

resp info() {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    {
        rapidjson::Value data;
        data.SetObject();

        // use StringRef as strings have safe lifetime (const char literals)
        data.AddMember("hash", rapidjson::Value().SetString(rapidjson::StringRef(cw::build::git_hash)), allocator);
        data.AddMember("branch", rapidjson::Value().SetString(rapidjson::StringRef(cw::build::git_branch)), allocator);
        data.AddMember("revision", cw::build::git_revision, allocator);
        r.first.AddMember("data", data, allocator);
    }
    r.second = boost::beast::http::status::ok;
    return r;
}

resp commandReturn(error_wrapper e, const std::string& failType = "Running command failed", boost::beast::http::status statusFail=boost::beast::http::status::ok) {
    if (e) {
        return json_error(e.with_msg(failType).with_status(static_cast<int>(statusFail)));
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
resp containerReturn(const error_wrapper& e, const std::vector<T>& entry) {
    if (e) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.first.SetObject();

        rapidjson::Value entryArr;
        entryArr.SetArray();
        for (const auto& v : entry) {
            rapidjson::Document subdocument(&r.first.GetAllocator());
            cw::batch::json::serialize(v, subdocument);
            entryArr.PushBack(subdocument, allocator);
        }
        r.first.AddMember("data", entryArr, allocator);
        r.second = boost::beast::http::status::ok;
        return r;
    }
}

resp getBatchInfoReturn(const error_wrapper& e, const cw::batch::BatchInfo& batchinfo) {
    if (e) {
        return json_error(e);
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


resp detectReturn(const error_wrapper& e, bool detected) {
    if (e.ec() != std::error_code(error_type::command_not_found)) { // ignore notfound error as that simply means batch not detected
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            data.AddMember("detected", detected, allocator);
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}



resp runJobReturn(const error_wrapper& e, const std::string& jobName) {
    if (e) {
        return json_error(e);
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

resp valid_login(const std::string& username, const std::set<std::string>& scopes) {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.second = boost::beast::http::status::ok;
    r.first.SetObject();
    {
        rapidjson::Value data;
        data.SetObject();
        data.AddMember("user", username, allocator);

        {
            rapidjson::Value scopesarr;
            scopesarr.SetArray();
            for (const auto& scope : scopes) {
                    rapidjson::Value val(scope.c_str(), allocator);
                    scopesarr.PushBack(val, allocator);
            }
            data.AddMember("scopes", scopesarr, allocator);
        }

        r.first.AddMember("data", data, allocator);
    }

    return r;
}

resp writingCredentialsReturn(const error_wrapper& e, boost::optional<std::pair<std::string, std::set<std::string>>> data, boost::beast::http::status status=boost::beast::http::status::created) {
    if (data.has_value()) {
        if (e) return commandReturn(e, "Writing credentials failed", status);
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = status;
        r.first.SetObject();
        r.first.AddMember("username", data->first, allocator);
        {
            rapidjson::Value scopesarr;
            scopesarr.SetArray();
            for (const auto& scope : data->second) {
                    rapidjson::Value val(scope.c_str(), allocator);
                    scopesarr.PushBack(val, allocator);
            }
            r.first.AddMember("scopes", scopesarr, allocator);
        }
        return r;
    } else {
        return commandReturn(e, "Writing credentials failed", status);
    }
}

}
}
}

#endif /* BOOST_PROXY_RESPONSE */
