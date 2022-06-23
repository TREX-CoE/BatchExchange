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

#include "batchsystem/json.h"
#include "proxy/build_data.h"

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

resp notfoundError(const std::string& msg) {
    return json_error("NotFound", msg, boost::beast::http::status::not_found);
}


resp invalidBatch() {
    return json_error("BatchsystemInvalid", "Invalid batchsystem selected, use one of: pbs | slurm | lsf", boost::beast::http::status::bad_request);
}


resp commandUnknown(const std::string& command) {
    return validationError("Unknown command: "+command);
}

resp commandUnsupported() {
    return json_error("CommandUnsupported", "Command not supported by batchsystem", boost::beast::http::status::bad_request);
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
    // use StringRef as strings have safe lifetime (const char literals)
    r.first.AddMember("hash", rapidjson::Value().SetString(rapidjson::StringRef(cw::build::git_hash)), allocator);
    r.first.AddMember("branch", rapidjson::Value().SetString(rapidjson::StringRef(cw::build::git_branch)), allocator);
    r.first.AddMember("revision", cw::build::git_revision, allocator);
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


resp detectReturn(std::error_code ec, bool detected) {
    if (ec && ec.value() != 2) { // ignore notfound error as that simply means batch not detected
        return json_error_ec(ec);
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

resp writingCredentialsReturn(std::error_code ec, boost::optional<std::pair<std::string, std::set<std::string>>> data, boost::beast::http::status status=boost::beast::http::status::created) {
    if (data.has_value()) {
        if (ec) return commandReturn(ec, "Writing credentials failed", status);
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
        return commandReturn(ec, "Writing credentials failed", status);
    }
}

}
}
}

#endif /* BOOST_PROXY_RESPONSE */
