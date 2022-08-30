#include "proxy/handler.h"

#include "proxy/build_data.h"
#include "proxy/credentials.h"
#include "proxy/batchsystem_json.h"
#include "proxy/batchsystem_process.h"
#include "proxy/xcat_http.h"
#include "proxy/globals.h"
#include "proxy/uri.h"
#include "proxy/response.h"
#include "proxy/error.h"
#include "proxy/error_wrapper.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <thread>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/make_unique.hpp>
#include <boost/process.hpp>
#include <boost/asio/error.hpp>

#include "batchsystem/batchsystem.h"
#include "xcat/xcat.h"


namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>

namespace {

using namespace cw::proxy;
using namespace cw::batch;
using namespace cw::error;
using namespace cw::helper::uri;

constexpr unsigned int timeout_cmd = 15000;
constexpr unsigned int timeout_xcat_http = 15000;

std::vector<std::string> getFilter(const rapidjson::Document& indocument, const Uri& uri) {
    std::vector<std::string> filters;
    if (uri.has_value() && uri.query.count("filter")) {
        std::string filter = uri.query.at("filter");
        cw::helper::splitString(filter, std::string(","), [&filters, &filter](size_t start, size_t end){
            filters.push_back(filter.substr(start, end));
            return true;
        });
    } else if (!indocument.HasParseError() && indocument.IsObject() && indocument.HasMember("filter") && indocument["filter"].IsArray()) {
        for (const auto& o : indocument["filter"].GetArray()) {
            if (o.IsString()) filters.push_back(o.GetString());
        }
    }
    return filters;
}

std::string jsonToString(const rapidjson::Document& document) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    return buffer.GetString();
}

void to_response(http::response<http::string_body>& res, const cw::proxy::response::resp& r) {
    res.result(r.second);
    res.set(http::field::content_type, "application/json");
    res.body() = jsonToString(r.first);
    res.prepare_payload();
}

bool parseSystem(System& system, const std::string& input) {
    if (input == "pbs") {
        system = System::Pbs;
        return true;
    } else if (input == "slurm") {
        system = System::Slurm;
        return true;
    } else if (input == "lsf") {
        system = System::Lsf;
        return true;
    }
    return false;
}

std::shared_ptr<BatchInterface> getBatch(boost::asio::io_context& ioc, const rapidjson::Document& document, const Uri& uri, boost::optional<System> system) {
    if (uri.has_value()) {
        if (uri.query.count("batchsystem")) {
            System sys;
            if (parseSystem(sys, uri.query.at("batchsystem"))) system = sys;
        }
    }

    if (document.IsObject() && document.HasMember("batchsystem") && document["batchsystem"].IsString()) {
        System sys;
        parseSystem(sys, document["batchsystem"].GetString());
        system = sys;
    }


    if (!system.has_value()) return nullptr;

    return create_batch(system.value(), [&ioc](cw::batch::Cmd cmd, auto resp) {
        cw::proxy::batch::runCommand(ioc, cmd, resp, timeout_cmd);
    });
}

std::shared_ptr<::xcat::Xcat> getXcat(boost::asio::io_context& ioc, const cw::proxy::XcatOptions& opts, std::error_code& ec) {

    if (opts.host.empty()) {
        ec = error_type::xcat_host_missing;
        return nullptr;
    }
    if (opts.port.empty()) {
        ec = error_type::xcat_port_missing;
        return nullptr;
    } 

    if (opts.ssl) {
        std::shared_ptr<::xcat::Xcat> xcat_session{new ::xcat::Xcat{[&ioc, opts](::xcat::ApiCallRequest req, auto resp) {
            boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};

            // Verify the remote server's certificate
            if (opts.ssl_verify) ctx.set_verify_mode(boost::asio::ssl::verify_peer);

            cw::proxy::xcat::runHttps(ioc, req, resp, timeout_xcat_http, opts.host, opts.port, std::move(ctx));

        }}};
        xcat_session->set_token(opts.token, opts.expires);
        xcat_session->set_credentials(opts.user, opts.password);
        return xcat_session;
    } else {
        std::shared_ptr<::xcat::Xcat> xcat_session{new ::xcat::Xcat{[&ioc, opts](::xcat::ApiCallRequest req, auto resp) {
            cw::proxy::xcat::runHttp(ioc, req, resp, timeout_xcat_http, opts.host, opts.port);
        }}};
        xcat_session->set_token(opts.token, opts.expires);
        xcat_session->set_credentials(opts.user, opts.password);
        return xcat_session;
    }
}

void res_add_json_string(http::response<http::string_body>& res, std::string s) {
    res.result(http::status::ok);
    res.set(http::field::content_type, "application/json");
    res.body() = std::move(s);
    res.prepare_payload();
}

response::resp ws_login(std::set<std::string>& scopes, std::string& user, const rapidjson::Document& indocument) {
    if (!indocument.HasMember("user")) return response::json_error(error_wrapper(error_type::user_missing));
    if (!indocument["user"].IsString()) return response::json_error(error_wrapper(error_type::user_not_string));

    if (!indocument.HasMember("password")) return response::json_error(error_wrapper(error_type::password_missing));
    if (!indocument["password"].IsString()) return response::json_error(error_wrapper(error_type::password_not_string));

    std::string username = indocument["user"].GetString();
    auto ec = cw::globals::creds_get(username, indocument["password"].GetString(), scopes);
    if (ec) {
        return response::json_error(error_wrapper(ec).with_msg(username));
    } else {
        user = username;
        return response::valid_login(username, scopes);
    }
}

response::resp ws_setBatchsystem(boost::optional<System>& system, const rapidjson::Document& indocument) {
    if (!indocument.HasMember("batchsystem")) return response::json_error(error_wrapper(error_type::batchsystem_missing));
    if (!indocument["batchsystem"].IsString()) return response::json_error(error_wrapper(error_type::batchsystem_not_string));
    System s;
    if (!parseSystem(s, indocument["batchsystem"].GetString())) return response::json_error(error_wrapper(error_type::batchsystem_unknown));
    system = s;
    return response::commandSuccess();
}

std::error_code xcat_get_opts_uri(const Uri& uri, cw::proxy::XcatOptions& opts) {
    if (uri.has_value()) {
        if (uri.query.count("host")) {
            opts.host = uri.query.at("host");
        }
        if (uri.query.count("port")) {
            opts.port = uri.query.at("port");
        }
        if (uri.query.count("token")) {
            opts.token = uri.query.at("token");
        }
        if (uri.query.count("user")) {
            opts.user = uri.query.at("user");
        }
        if (uri.query.count("password")) {
            opts.password = uri.query.at("password");
        }
        if (uri.query.count("ssl")) {
            opts.ssl = uri.query.at("ssl") != "false";
        }
        if (uri.query.count("ssl_verify")) {
            opts.ssl_verify = uri.query.at("ssl_verify") == "true";
        }
    }
    return {};
}

std::error_code xcat_get_opts_json(const rapidjson::Document& indocument, cw::proxy::XcatOptions& opts) {
    if (indocument.HasParseError() || !indocument.IsObject()) return {};
    if (indocument.HasMember("host") && indocument["host"].IsString()) {
        opts.host = indocument["host"].GetString();
    }
    if (indocument.HasMember("port")) {
        if (indocument["port"].IsString()) {
            opts.port = indocument["port"].GetString();
        } else if (indocument["port"].IsInt()) {
            opts.port = std::to_string(indocument["port"].GetInt());
        }
    }
    if (indocument.HasMember("token") && indocument["token"].IsString()) {
        opts.token = indocument["token"].GetString();
    }
    if (indocument.HasMember("user") && indocument["user"].IsString()) {
        opts.user = indocument["user"].GetString();
    }
    if (indocument.HasMember("password") && indocument["password"].IsString()) {
        opts.password = indocument["password"].GetString();
    }
    if (indocument.HasMember("expires") && indocument["expires"].IsUint()) {
        opts.expires = indocument["expires"].GetUint();
    }
    if (indocument.HasMember("ssl") && indocument["ssl"].IsBool()) {
        opts.ssl = indocument["ssl"].GetBool();
    }
    if (indocument.HasMember("ssl_verify") && indocument["ssl_verify"].IsBool()) {
        opts.ssl_verify = indocument["ssl_verify"].GetBool();
    }
    return {};
}

response::resp ws_xcat_set(cw::proxy::XcatOptions& opts, const rapidjson::Document& indocument) {
    auto ec = xcat_get_opts_json(indocument, opts);
    if (ec) return response::json_error(error_wrapper(ec));
    return response::commandSuccess();
}

template<typename CallbackF>
void write_creds_async(boost::asio::io_context& ioc_, const cw::helper::credentials::dict& creds, CallbackF callbackF) {
    auto stream = std::make_shared<boost::asio::posix::stream_descriptor>(ioc_, ::creat(cw::globals::cred_file().c_str(), 0755));
    auto s = std::make_shared<std::string>();
    cw::helper::credentials::write(creds, *s);
    boost::asio::async_write(*stream, boost::asio::buffer(*s), boost::asio::transfer_all(), [stream, s, creds, callbackF](beast::error_code ec, size_t len) mutable {
        (void)len;
        if (ec) {
            callbackF(error_wrapper(error_type::writing_credentials_error).with_base(ec));
        } else {
            // store new credentials in global after successfull write
            cw::globals::creds(creds);
            callbackF(error_wrapper());
        }
    });
}

template <typename CheckAuth, typename Send>
void f_usersEdit(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, boost::asio::io_context& ioc, std::string* user, std::set<std::string>* current_scopes) {
    if (!check_auth({"users_edit"})) return;

    std::error_code ec;
    auto o = cw_proxy_batch::usersAdd(indocument, uri, true, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    std::string username = std::get<0>(*o);
    std::set<std::string> scopes = std::get<1>(*o);
    const std::string& password = std::get<2>(*o);

    auto creds = cw::globals::creds();
    auto it = creds.find(username);
    if (it != creds.end()) return send(response::json_error(error_wrapper(error_type::user_not_found)));

    if (!password.empty()) {
        // create new password
        cw::helper::credentials::set_password(it->second, password);
    }

    if (!scopes.count("")) {
        // override scopes
        it->second.scopes = scopes;
    }

    if (user != nullptr && current_scopes != nullptr && username == *user) {
        // update new scopes
        *current_scopes = scopes;
    }

    write_creds_async(ioc, creds, [send, user=std::move(username), s=std::move(scopes)](auto e) mutable {
        return send(response::writingCredentialsReturn(e, {{user, s}}, boost::beast::http::status::created));
    });
}

template <typename CheckAuth, typename Send>
void f_usersAdd(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, boost::asio::io_context& ioc) {
    if (!check_auth({"users_add"})) return;

    std::error_code ec;
    auto o = cw_proxy_batch::usersAdd(indocument, uri, false, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    auto creds = cw::globals::creds();
    std::string username = std::get<0>(*o);
    if (creds.find(username) != creds.end()) return send(response::json_error(error_wrapper(error_type::conflict_user)));

    std::set<std::string> scopes = std::get<1>(*o);

    const std::string& password = std::get<2>(*o);
    if (password.empty()) return send(response::json_error(error_wrapper(error_type::invalid_password_empty)));

    cw::helper::credentials::set_user(creds, std::get<0>(*o), std::get<1>(*o), std::get<2>(*o));
    write_creds_async(ioc, creds, [send, user=std::move(username), s=std::move(scopes)](auto e) mutable {
        return send(response::writingCredentialsReturn(e, {{user, s}}, boost::beast::http::status::created));
    });
}

template <typename CheckAuth, typename Send>
void f_usersDelete(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, boost::asio::io_context& ioc, std::string* user, std::set<std::string>* scopes) {
    if (!check_auth({"users_delete"})) return;

    std::error_code ec;
    auto username = cw_proxy_batch::usersDelete(indocument, uri, ec);
    if (ec) return send(response::json_error(error_wrapper(ec)));

    auto creds = cw::globals::creds();
    auto it = creds.find(username);
    if (it == creds.end()) return send(response::json_error(error_wrapper(error_type::user_not_found)));
    creds.erase(it);
    if (user != nullptr && username == *user) {
        // deleting current user
        *user = "";
        if (scopes != nullptr) scopes->clear();
    }

    write_creds_async(ioc, creds, [send](auto e) mutable {
        return send(response::writingCredentialsReturn(e, {}, boost::beast::http::status::ok));
    });
}

template <typename CheckAuth, typename Send>
void f_jobsSubmit(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_submit"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->runJob(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::runJob(indocument, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->runJob(*o, [batch, send](std::string jobName, std::error_code e) mutable {
        return send(response::runJobReturn(error_wrapper(e), jobName));
    });
}

template <typename CheckAuth, typename Send>
void f_jobsDeleteById(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_delete"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->deleteJobById(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::deleteJobById(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->deleteJobById(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_jobsDeleteByUser(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_user_delete"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->deleteJobByUser(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::deleteJobByUser(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->deleteJobByUser(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_setNodeState(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_state_edit"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->changeNodeState(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::changeNodeState(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->changeNodeState(std::get<0>(*o), std::get<1>(*o), std::get<2>(*o), std::get<3>(*o), std::get<4>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_setQueueState(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"queues_state_edit"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->setQueueState(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::setQueueState(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->setQueueState(std::get<0>(*o), std::get<1>(*o), std::get<2>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_setNodeComment(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_comment_edit"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->setNodeComment(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::setNodeComment(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->setNodeComment(std::get<0>(*o), std::get<1>(*o), std::get<2>(*o), std::get<3>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_holdJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_hold"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->holdJob(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::holdJob(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->holdJob(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_releaseJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_release"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->releaseJob(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::releaseJob(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->releaseJob(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_suspendJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_suspend"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->suspendJob(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::suspendJob(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->suspendJob(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_resumeJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_resume"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->resumeJob(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::resumeJob(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->resumeJob(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}

template <typename CheckAuth, typename Send>
void f_rescheduleRunningJobInQueue(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_reschedule"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->rescheduleRunningJobInQueue(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::rescheduleRunningJobInQueue(indocument, uri, ec);
    if (!o) return send(response::json_error(error_wrapper(ec)));

    batch->rescheduleRunningJobInQueue(std::get<0>(*o), std::get<1>(*o), [batch, send](std::error_code e) mutable {
        return send(response::commandReturn(error_wrapper(e)));
    });
}


template <typename CheckAuth, typename Send>
void f_getJobs(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_info"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->getJobs(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    std::error_code ec;
    auto o = cw_proxy_batch::getJobs(indocument, uri, ec);
    if (ec) return send(response::json_error(error_wrapper(ec)));

    batch->getJobs(o, [batch, send](auto container, std::error_code e) mutable {
        return send(response::containerReturn(error_wrapper(e), container));
    });
}

template <typename CheckAuth, typename Send>
void f_getQueues(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"queues_info"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->getQueues(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    batch->getQueues([batch, send](auto container, std::error_code e) mutable {
        return send(response::containerReturn(error_wrapper(e), container));
    });
}

template <typename CheckAuth, typename Send>
void f_getNodes(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_info"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->getNodes(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));
    std::error_code ec;
    auto o = cw_proxy_batch::getNodes(indocument, uri, ec);
    if (ec) return send(response::json_error(error_wrapper(ec)));

    batch->getNodes(o, [batch, send](auto container, std::error_code e) mutable {
        return send(response::containerReturn(error_wrapper(e), container));
    });
}

template <typename CheckAuth, typename Send>
void f_getBatchInfo(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"batch_info"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    if (!batch->getBatchInfo(supported)) return send(response::json_error(error_wrapper(error_type::command_unsupported).with_status(400)));

    batch->getBatchInfo([batch, send](auto batchinfo, std::error_code ec) mutable {
        return send(response::getBatchInfoReturn(error_wrapper(ec), batchinfo));
    });
}

template <typename CheckAuth, typename Send>
void f_detect(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"batch_detect"})) return;

    auto batch = getBatch(ioc, indocument, uri, system);
    if (!batch) return send(response::json_error(error_wrapper(error_type::batchsystem_unknown)));

    batch->detect([batch, send](bool detected, std::error_code ec) mutable {
        return send(response::detectReturn(error_wrapper(ec), detected));
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_login(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_login"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);
    if (opts.user.empty()) return send(response::json_error(error_wrapper(error_type::xcat_user_missing)));
    if (opts.password.empty()) return send(response::json_error(error_wrapper(error_type::xcat_password_missing)));

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));

    xcat_session->get_token([xcat_session, send, &opts](auto token, auto expires, auto ec) mutable {
        // store token
        opts.token = token;
        opts.expires = expires;
        return send(response::xcatTokenReturn(error_wrapper(ec.ec).with_msg(ec.msg), token, expires));
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_getNodes(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_nodes"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    xcat_session->get_nodes([xcat_session, send](auto nodes, auto ec) mutable {
        return send(response::xcatNodesReturn(error_wrapper(ec.ec).with_msg(ec.msg), nodes));
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_getGroups(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_groups"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    xcat_session->get_groups(getFilter(indocument, uri), [xcat_session, send](auto groups, auto ec) mutable {
        return send(response::xcatGroupsReturn(error_wrapper(ec.ec).with_msg(ec.msg), groups));
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_getOsimages(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_osimages"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    xcat_session->get_osimages(getFilter(indocument, uri), [xcat_session, send](auto images, auto ec) mutable {
        return send(response::xcatOsimagesReturn(error_wrapper(ec.ec).with_msg(ec.msg), images));
    });
}


template <typename CheckAuth, typename Send>
void f_xcat_setBootstate(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_set_bootstate"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    std::string osimage;
    if (uri.has_value() && uri.query.count("osimage")) {
        osimage = uri.query.at("osimage");
    } else if (!indocument.HasParseError() && indocument.IsObject() && indocument.HasMember("osimage") && indocument["osimage"].IsString()) {
        osimage = indocument["osimage"].GetString();
    }
    if (osimage.empty()) return send(response::json_error(error_wrapper(error_type::xcat_osimage_missing)));

    xcat_session->set_bootstate(getFilter(indocument, uri), osimage, [xcat_session, send](auto nodes, auto ec) mutable {
        (void)nodes;
        return send(ec.ec ? response::json_error(error_wrapper(ec.ec).with_msg(ec.msg)) : response::commandSuccess());
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_setNextboot(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_set_nextboot"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    std::string order;
    if (uri.has_value() && uri.query.count("order")) {
        order = uri.query.at("order");
    } else if (!indocument.HasParseError() && indocument.IsObject() && indocument.HasMember("order") && indocument["order"].IsString()) {
        order = indocument["order"].GetString();
    }
    if (order.empty()) return send(response::json_error(error_wrapper(error_type::xcat_order_missing)));

    xcat_session->set_nextboot(getFilter(indocument, uri), order, [xcat_session, send](auto nodes, auto ec) mutable {
        (void)nodes;
        return send(ec.ec ? response::json_error(error_wrapper(ec.ec).with_msg(ec.msg)) : response::commandSuccess());
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_setPowerstate(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_set_powerstate"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    std::string action;
    if (uri.has_value() && uri.query.count("action")) {
        action = uri.query.at("action");
    } else if (!indocument.HasParseError() && indocument.IsObject() && indocument.HasMember("action") && indocument["action"].IsString()) {
        action = indocument["action"].GetString();
    }
    if (action.empty()) return send(response::json_error(error_wrapper(error_type::xcat_action_missing)));

    xcat_session->set_nextboot(getFilter(indocument, uri), action, [xcat_session, send](auto nodes, auto ec) mutable {
        (void)nodes;
        return send(ec.ec ? response::json_error(error_wrapper(ec.ec).with_msg(ec.msg)) : response::commandSuccess());
    });
}

template <typename CheckAuth, typename Send>
void f_xcat_setGroupAttributes(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, cw::proxy::XcatOptions& opts, boost::asio::io_context& ioc) {
    if (!check_auth({"xcat_set_group_attributes"})) return;

    xcat_get_opts_uri(uri, opts);
    xcat_get_opts_json(indocument, opts);

    std::error_code ec_session;
    auto xcat_session = getXcat(ioc, opts, ec_session);
    if (ec_session) return send(response::json_error(error_wrapper(ec_session)));
    if (!xcat_session->check_auth()) return send(response::json_error(error_wrapper(error_type::xcat_auth_missing)));

    if (indocument.HasParseError() || !indocument.IsObject() || !indocument.HasMember("attributes")) return send(response::json_error(error_wrapper(error_type::xcat_attributes_missing)));
    
    std::map<std::string, std::string> attributes;
    for (const auto& p : indocument["attributes"].GetObject()) {
        if (p.value.IsString()) {
            attributes[p.name.GetString()] = p.value.GetString();
        }
    }


    xcat_session->set_group_attributes(getFilter(indocument, uri), attributes, [xcat_session, send](auto nodes, auto ec) mutable {
        (void)nodes;
        return send(ec.ec ? response::json_error(error_wrapper(ec.ec).with_msg(ec.msg)) : response::commandSuccess());
    });
}

}

namespace cw {
namespace proxy {
namespace handler {

namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>

void ws(std::function<void(std::string)> send_, boost::asio::io_context& ioc, std::string input, std::set<std::string>& scopes, std::string& user, boost::optional<System>& selectedSystem, cw::proxy::XcatOptions& xcat_opts) {
    cw::helper::uri::Uri url;

    rapidjson::Document indocument;
    indocument.Parse(input);
    if (indocument.HasParseError()) {
        return send_(jsonToString(response::json_error(error_wrapper(error_type::body_not_json)).first));
    }
    if (!indocument.IsObject()) {
        return send_(jsonToString(response::json_error(error_wrapper(error_type::body_not_object)).first));
    }

    bool tag_given = false;
    std::string tag;
    if (indocument.HasMember("tag")) {
        if (!indocument["tag"].IsString()) return send_(jsonToString(response::json_error(error_wrapper(error_type::tag_not_string)).first));
        tag = indocument["tag"].GetString();
        tag_given = true;
    }

    // note capture send functor by copy to ensure tag's lifetime
    auto send = [send_, tag, tag_given](response::resp r) {
        if (tag_given) r.first.AddMember("tag", tag, r.first.GetAllocator());
        send_(jsonToString(r.first));
    };

    if (!indocument.HasMember("command")) return send(response::json_error(error_wrapper(error_type::socket_command_missing)));
    if (!indocument["command"].IsString()) return send(response::json_error(error_wrapper(error_type::socket_command_not_string)));
    std::string command = indocument["command"].GetString();

    auto check_auth =
    [send, &scopes](std::initializer_list<std::string> scopes_)
    {
        for (const auto& scope : scopes_) {
            if (!scopes.count(scope)) {
                send(response::json_error(error_wrapper(error_type::login_scope_missing).with_msg(scope)));
                return false;
            }
        }
        return true;
    };

    try {
        if (command == "asyncapi.json") {
            return send_(cw::build::asyncapi_json);
        } else if (command == "openapi.json") {
            return send_(cw::build::openapi_json);
        } else if (command == "info") {
            return send(response::info());
        } else if (command == "login") {
            return send(ws_login(scopes, user, indocument));
        } else if (command == "logout") {
            scopes.clear();
            user = "";
            return send(response::commandSuccess());
        } else if (command == "setBatchsystem") {
            return send(ws_setBatchsystem(selectedSystem, indocument));
        } else if (command == "detect") {
            f_detect(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "getBatchInfo") {
            f_getBatchInfo(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "getNodes") {
            f_getNodes(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "getQueues") {
            f_getQueues(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "getJobs") {
            f_getJobs(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "usersAdd") {
            f_usersAdd(check_auth, send, indocument, url, ioc);
        } else if (command == "usersEdit") {
            f_usersEdit(check_auth, send, indocument, url, ioc, &user, &scopes);
        } else if (command == "usersDelete") {
            f_usersDelete(check_auth, send, indocument, url, ioc, &user, &scopes);
        } else if (command == "jobsSubmit") {
            f_jobsSubmit(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "jobsDeleteById") {
            f_jobsDeleteById(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "jobsDeleteByUser") {
            f_jobsDeleteByUser(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "setNodeState") {
            f_setNodeState(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "setQueueState") {
            f_setQueueState(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "setNodeComment") {
            f_setNodeComment(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "holdJob") {
            f_holdJob(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "releaseJob") {
            f_releaseJob(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "suspendJob") {
            f_suspendJob(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "resumeJob") {
            f_resumeJob(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "rescheduleJob") {
            f_rescheduleRunningJobInQueue(check_auth, send, indocument, url, selectedSystem, ioc);
        } else if (command == "xcat/login") {
            f_xcat_login(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/getNodes") {
            f_xcat_getNodes(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/getGroups") {
            f_xcat_getGroups(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/getOsimages") {
            f_xcat_getOsimages(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/setBootstate") {
            f_xcat_setBootstate(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/setNextboot") {
            f_xcat_setNextboot(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/setPowerstate") {
            f_xcat_setPowerstate(check_auth, send, indocument, url, xcat_opts, ioc);
        } else if (command == "xcat/setGroupAttributes") {
            f_xcat_setGroupAttributes(check_auth, send, indocument, url, opts, ioc);
        } else if (command == "xcat/set") {
            send(ws_xcat_set(xcat_opts, indocument));
        } else {
            send(response::json_error(error_wrapper(error_type::socket_command_unknown).with_msg(command)));
        }
    } catch (const std::system_error& e) {
        send(response::json_error(error_wrapper(e.code()).with_msg(e.what())));
    } catch (const std::exception& e) {
        send(response::json_error(error_wrapper(error_type::unhandled_exception).with_msg(e.what())));
    }
}

void rest(std::function<void(boost::beast::http::response<boost::beast::http::string_body>)> send_, boost::asio::io_context& ioc, boost::beast::http::request<boost::beast::http::string_body> req) {
    auto content_type = req[http::field::content_type];

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(req.keep_alive());

    auto check_auth =
    [send_, &res, &req](const std::set<std::string>& scopes = {}) mutable
    {
        std::string user, pass;
        if (cw::http::parse_auth_header(req[http::field::authorization], user, pass)) {
            auto ec = cw::globals::creds_check(user, pass, scopes);
            if (!ec) {
                return true;
            }
            to_response(res, response::json_error(error_wrapper(ec)));
        } else {
            to_response(res, response::json_error(error_wrapper(error_type::login_auth_header_invalid)));
        }
        send_(std::move(res));
        return false;
    };

    auto check_json =
    [send_, res, &content_type, &req](rapidjson::Document& document, bool optional=false) mutable
    {
        if (content_type != "application/json") {
            if (!optional) {
                res.result(http::status::unsupported_media_type);
                send_(std::move(res));
            }
            return false;
        }

        document.Parse(req.body());
        if (document.HasParseError()) {
            if (!optional) {
                res.result(http::status::unsupported_media_type);
                send_(std::move(res));
            }
            return false;
        }

        return true;
    };

    auto send = [res, send_](response::resp r) mutable {
        to_response(res, r);
        return send_(std::move(res));
    };

    rapidjson::Document indocument;

    cw::helper::uri::Uri url;
    std::string target = std::string(req.target());
    if (!cw::helper::uri::Uri::parse(url, target)) return send(response::json_error(error_wrapper(error_type::invalid_uri).with_msg(std::move(target))));

    try {
        if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "asyncapi.json") {
            res_add_json_string(res, cw::build::asyncapi_json);
            return send_(std::move(res));
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "openapi.json") {
            res_add_json_string(res, cw::build::openapi_json);
            return send_(std::move(res));
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "info") {
            return send(response::info());
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "state") {
            f_detect(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "batchinfo") {
            f_getBatchInfo(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "nodes") {
            f_getNodes(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "queues") {
            f_getQueues(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "jobs") {
            f_getJobs(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 1 && url.path[0] == "users") {
            if (!check_json(indocument)) return;
            f_usersAdd(check_auth, send, indocument, url.remove_prefix(1), ioc);
        } else if (req.method() == http::verb::patch && url.path.size() == 1 && url.path[0] == "users") {
            if (!check_json(indocument)) return;
            f_usersEdit(check_auth, send, indocument, url.remove_prefix(1), ioc, nullptr, nullptr);
        } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "users") {
            f_usersDelete(check_auth, send, indocument, url.remove_prefix(1), ioc, nullptr, nullptr);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[1] == "*" && url.path[2] == "submit") {
            if (!check_json(indocument)) return;
            f_jobsSubmit(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "jobs" && url.path[1] == "*") {
            f_jobsDeleteByUser(check_auth, send, indocument, url, {}, ioc);
        } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "jobs") {
            f_jobsDeleteById(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "nodes" && url.path[2] == "state") {
            if (!check_json(indocument)) return;
            f_setNodeState(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "queues" && url.path[2] == "state") {
            if (!check_json(indocument)) return;
            f_setQueueState(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "nodes" && url.path[2] == "comment") {
            if (!check_json(indocument)) return;
            f_setNodeComment(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "hold") {
            if (!check_json(indocument)) return;
            f_holdJob(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "release") {
            if (!check_json(indocument)) return;
            f_releaseJob(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "suspend") {
            if (!check_json(indocument)) return;
            f_suspendJob(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "resume") {
            if (!check_json(indocument)) return;
            f_resumeJob(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "reschedule") {
            if (!check_json(indocument)) return;
            f_rescheduleRunningJobInQueue(check_auth, send, indocument, url.remove_prefix(1), {}, ioc);
        } else if (req.method() == http::verb::post && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "login") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_login(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "nodes") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_getNodes(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "groups") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_getGroups(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::get && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "osimages") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_getOsimages(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::put && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "bootstate") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_setBootstate(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::put && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "nextboot") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_setNextboot(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::put && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "powerstate") {
            check_json(indocument, true);
            cw::proxy::XcatOptions opts;
            f_xcat_setPowerstate(check_auth, send, indocument, url, opts, ioc);
        } else if (req.method() == http::verb::put && url.path.size() == 2 && url.path[0] == "xcat" && url.path[1] == "groupattrs") {
            if (!check_json(indocument)) return;
            cw::proxy::XcatOptions opts;
            f_xcat_setGroupAttributes(check_auth, send, indocument, url, opts, ioc);
        } else {
            send(response::json_error(error_wrapper(error_type::request_unknown).with_msg(std::string(boost::beast::http::to_string(req.method())) + " " + std::string(req.target()))));
        }
    } catch (const std::system_error& e) {
        send(response::json_error(error_wrapper(e.code()).with_msg(e.what())));
    } catch (const std::exception& e) {
        send(response::json_error(error_wrapper(error_type::unhandled_exception).with_msg(e.what())));
    }
}

}
}
}
