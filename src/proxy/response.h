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
#include "xcat/xcat.h"

namespace {

using namespace cw::error;

int to_statuscode(const std::error_code& e) {
    if (e.category() == trex_category()) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
        switch (static_cast<error_type>(e.value())) {
            case error_type::socket_command_missing: return 400;
            case error_type::invalid_password_empty: return 400;
            case error_type::invalid_uri: return 400;
            case error_type::batchsystem_missing: return 400;
            case error_type::batchsystem_unknown: return 400;
            case error_type::user_missing: return 400;
            case error_type::user_not_string: return 400;
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

resp commandSuccess(boost::beast::http::status status=boost::beast::http::status::ok) {
    resp r;
    rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
    r.first.SetObject();
    {
        rapidjson::Value data;
        data.SetObject();
        data.AddMember("success", true, allocator);
        r.first.AddMember("data", data, allocator);
    }
    r.second = status;
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
        return commandSuccess();
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
    if (e.ec() && e.ec() != std::error_code(error_type::command_not_found)) { // ignore notfound error as that simply means batch not detected
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

resp xcatTokenReturn(const error_wrapper& e, std::string token, unsigned long int expires) {
    if (e.ec()) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            data.AddMember("token", token, allocator);
            data.AddMember("expires", expires, allocator);
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

resp xcatNodesReturn(const error_wrapper& e, std::map<std::string, ::xcat::NodeInfo> nodes) {
    if (e.ec()) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            for (const auto& p : nodes) {
                rapidjson::Value node;
                node.SetObject();
                node.AddMember("name", p.second.name, allocator);
                node.AddMember("postscripts", p.second.postscripts, allocator);
                node.AddMember("postbootscripts", p.second.postbootscripts, allocator);
                node.AddMember("installnic", p.second.installnic, allocator);
                node.AddMember("primarynic", p.second.primarynic, allocator);
                node.AddMember("mac", p.second.mac, allocator);

                for (const auto& item: p.second.extra) {
                    rapidjson::Value key(item.first.c_str(), allocator);
                    rapidjson::Value val(item.second.c_str(), allocator);
                    node.AddMember(key, val, allocator);
                }

                rapidjson::Value groups;
                groups.SetArray();
                for (const auto& group : p.second.groups) {
                    rapidjson::Value g(group, allocator);
                    groups.PushBack(g, allocator);
                }
                node.AddMember("groups", groups, allocator);

                rapidjson::Value key(p.first.c_str(), allocator);
                data.AddMember(key, node, allocator);
            }
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

resp xcatGroupsReturn(const error_wrapper& e, std::map<std::string, ::xcat::GroupInfo> groups) {
    if (e.ec()) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            for (const auto& p : groups) {
                rapidjson::Value node;
                node.SetObject();
                node.AddMember("name", p.second.name, allocator);
                node.AddMember("mgt", p.second.mgt, allocator);
                node.AddMember("netboot", p.second.netboot, allocator);

                rapidjson::Value members;
                members.SetArray();
                for (const auto& group : p.second.members) {
                    rapidjson::Value g(group, allocator);
                    members.PushBack(g, allocator);
                }
                node.AddMember("members", members, allocator);

                rapidjson::Value key(p.first.c_str(), allocator);
                data.AddMember(key, node, allocator);
            }
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

resp xcatOsimagesReturn(const error_wrapper& e, std::map<std::string, ::xcat::OsimageInfo> groups) {
    if (e.ec()) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            for (const auto& p : groups) {
                rapidjson::Value node;
                node.SetObject();
                node.AddMember("name", p.second.name, allocator);
                node.AddMember("profile", p.second.profile, allocator);
                node.AddMember("osname", p.second.osname, allocator);
                node.AddMember("osarch", p.second.osarch, allocator);
                node.AddMember("osvers", p.second.osvers, allocator);
                node.AddMember("provmethod", p.second.provmethod, allocator);
                rapidjson::Value key(p.first.c_str(), allocator);
                data.AddMember(key, node, allocator);
            }
            r.first.AddMember("data", data, allocator);
        }
        return r;
    }
}

resp xcatBootstateReturn(const error_wrapper& e, std::map<std::string, std::string> groups) {
    if (e.ec()) {
        return json_error(e);
    } else {
        resp r;
        rapidjson::Document::AllocatorType& allocator = r.first.GetAllocator();
        r.second = boost::beast::http::status::ok;
        r.first.SetObject();
        {
            rapidjson::Value data;
            data.SetObject();
            for (const auto& p : groups) {
                rapidjson::Value node;
                node.SetObject();
                node.AddMember("bootstate", p.second, allocator);
                rapidjson::Value key(p.first.c_str(), allocator);
                data.AddMember(key, node, allocator);
            }
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
