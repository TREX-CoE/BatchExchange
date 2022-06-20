#include "proxy/handler.h"

#include "proxy/openapi_json.h"
#include "proxy/credentials.h"
#include "proxy/batchsystem_json.h"
#include "proxy/batchsystem_process.h"
#include "proxy/globals.h"
#include "proxy/uri.h"
#include "proxy/response.h"
#include "proxy/y_combinator.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "nonstd/invoke.hpp"

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


namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>

namespace {

using namespace cw::proxy;
using namespace cw::batch;
using namespace cw::helper::uri;

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


template <typename AsyncF, typename CallbackF>
void run_async(boost::asio::io_context& ioc_, AsyncF asyncF, CallbackF callbackF) {
    ioc_.post(cw::helper::y_combinator_shared([asyncF, callbackF, &ioc_](auto handler) mutable {
        try {
            if (asyncF()) {
                callbackF(boost::system::error_code());
                return;
            }
        } catch (const boost::process::process_error& e) {
            callbackF(e.code());
            return;
        }
        ioc_.post(handler);
    }));
}

template <typename T, typename AsyncF, typename CallbackF>
void run_async_state(boost::asio::io_context& ioc_, AsyncF asyncF, CallbackF callbackF) {
    ioc_.post(cw::helper::y_combinator_shared([state=T(), asyncF, callbackF, &ioc_](auto handler) mutable {
        try {
            if (asyncF(state)) {
                callbackF(boost::system::error_code(), std::move(state));
                return;
            }
        } catch (const boost::process::process_error& e) {
            callbackF(e.code(), std::move(state));
            return;
        }
        ioc_.post(handler);
    }));
}

bool parseSystem(System& system, const std::string& input) {
    if (input == "pbs") {
        system = System::Pbs;
        return true;
    } else if (input == "slurm") {
        system = System::Slurm;
        return true;
    } else if (input == "lsf") {
        system = System::Slurm;
        return true;
    }
    return false;
}

std::shared_ptr<BatchInterface> getBatch(const rapidjson::Document& document, const Uri& uri, cmd_f _func, boost::optional<System> system) {
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

    return create_batch(system.value(), std::move(_func));
}

void api_openapi(http::response<http::string_body>& res) {
    res.result(http::status::ok);
    res.set(http::field::content_type, "application/json");
    res.body() = cw::openapi::openapi_json;
    res.prepare_payload();
}

response::resp ws_login(std::set<std::string>& scopes, std::string& user, const rapidjson::Document& indocument) {
    if (!(indocument.HasMember("user") && indocument["user"].IsString())) return response::validationError("user invalid");
    if (!(indocument.HasMember("password") && indocument["password"].IsString())) return response::validationError("password invalid");
    std::string username = indocument["user"].GetString();
    if (cw::globals::creds_get(username, indocument["password"].GetString(), scopes)) {
        user = username; 
        return response::commandSuccess();
    } else {
        return response::invalid_login();
    }
}

response::resp ws_setBatchsystem(boost::optional<System>& system, const rapidjson::Document& indocument) {
    if (!indocument.HasMember("batchsystem")) return response::validationError("batchsystem not given");
    if (!indocument["batchsystem"].IsString()) return response::validationError("batchsystem is not a string");
    System s;
    if (!parseSystem(s, indocument["batchsystem"].GetString())) return response::validationError("batchsystem is not a valid choice");
    system = s;
    return response::commandSuccess();
}

template<typename CallbackF>
void write_creds_async(boost::asio::io_context& ioc_, const cw::helper::credentials::dict& creds, CallbackF callbackF) {
    auto stream = std::make_shared<boost::asio::posix::stream_descriptor>(ioc_, ::creat(cw::globals::cred_file().c_str(), 0755));
    auto s = std::make_shared<std::string>();
    cw::helper::credentials::write(creds, *s);
    boost::asio::async_write(*stream, boost::asio::buffer(*s), boost::asio::transfer_all(), [stream, s, creds, callbackF](beast::error_code ec, size_t len) mutable {
        (void)len;
        if (!ec) {
            // store new credentials in global after successfull write
            cw::globals::creds(creds);
        }
        callbackF(ec);
    });
}

template <typename CheckAuth, typename Send>
void f_usersAdd(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, boost::asio::io_context& ioc) {
    if (!check_auth({"users_add"})) return;

    std::string err;
    auto o = cw_proxy_batch::usersAdd(indocument, "", err);
    if (!o) return send(response::validationError(err));

    auto creds = cw::globals::creds();
    const std::string& username = std::get<0>(*o);
    if (creds.find(username) != creds.end()) return send(response::json_error("Conflict", "User already exists", http::status::conflict));
    nonstd::apply([&creds](auto&&... args){cw::helper::credentials::set_user(creds, args...);}, std::move(*o));
    write_creds_async(ioc, creds, [send](auto ec) mutable {
        return send(response::writingCredentialsReturn(ec, boost::beast::http::status::created));
    });
}

template <typename CheckAuth, typename Send>
void f_usersDelete(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, boost::asio::io_context& ioc, std::string* user, std::set<std::string>* scopes) {
    if (!check_auth({"users_delete"})) return;

    std::string err;
    auto username = cw_proxy_batch::usersDelete(indocument, uri, err);
    if (!err.empty()) return send(response::validationError(err));

    auto creds = cw::globals::creds();
    auto it = creds.find(username);
    if (it == creds.end()) return send(response::notfoundError("user " + username + " not found"));
    creds.erase(it);
    if (user != nullptr && username == *user) {
        // deleting current user
        *user = "";
        if (scopes != nullptr) scopes->clear();
    }

    write_creds_async(ioc, creds, [send](auto ec) mutable {
        return send(response::writingCredentialsReturn(ec, boost::beast::http::status::ok));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_jobsSubmit(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_submit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->runJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::runJob(indocument, err);
    if (!o) return send(response::validationError(err));
    auto f = batch->runJob(*o);

    run_async_state<std::string>(ioc, f, [batch, send](auto ec, std::string jobName) mutable {
        return send(response::runJobReturn(ec, jobName));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_jobsDeleteById(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_delete"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->deleteJobById(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::deleteJobById(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->deleteJobById(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_jobsDeleteByUser(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_user_delete"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->deleteJobByUser(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::deleteJobByUser(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->deleteJobByUser(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_changeNodeState(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_state_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->changeNodeState(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::changeNodeState(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->changeNodeState(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_setQueueState(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"queues_state_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->setQueueState(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::setQueueState(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->setQueueState(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_setNodeComment(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_comment_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->setNodeComment(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::setNodeComment(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->setNodeComment(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_holdJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_hold"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->holdJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::holdJob(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->holdJob(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_releaseJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->releaseJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::releaseJob(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->releaseJob(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_suspendJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->suspendJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::suspendJob(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->suspendJob(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_resumeJob(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->resumeJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::resumeJob(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->resumeJob(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_rescheduleRunningJobInQueue(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->rescheduleRunningJobInQueue(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::rescheduleRunningJobInQueue(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->rescheduleRunningJobInQueue(args...); }, std::move(*o));
    run_async(ioc, f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}


template <typename CheckAuth, typename Send, typename ExecCb>
void f_getJobs(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"jobs_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getJobs(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::getJobs(indocument, uri, err);
    if (!err.empty()) return send(response::validationError(err));

    run_async_state<std::vector<cw::batch::Job>>(ioc, [batch, f=batch->getJobs(o)](std::vector<cw::batch::Job>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_getQueues(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"queues_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getQueues(supported)) return send(response::commandUnsupported());

    run_async_state<std::vector<cw::batch::Queue>>(ioc, [batch, f=batch->getQueues()](std::vector<cw::batch::Queue>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_getNodes(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"nodes_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getNodes(supported)) return send(response::commandUnsupported());
    std::string err;
    auto o = cw_proxy_batch::getNodes(indocument, uri, err);
    if (!err.empty()) return send(response::validationError(err));

    run_async_state<std::vector<cw::batch::Node>>(ioc, [batch, f=batch->getNodes(o)](std::vector<cw::batch::Node>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_getBatchInfo(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"batch_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getBatchInfo(supported)) return send(response::commandUnsupported());

    run_async_state<BatchInfo>(ioc, [batch, f=batch->getBatchInfo()](BatchInfo& state){ return f(state); }, [send](auto ec, auto batchinfo) mutable {
        return send(response::getBatchInfoReturn(ec, batchinfo));
    });
}

template <typename CheckAuth, typename Send, typename ExecCb>
void f_detect(CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system, boost::asio::io_context& ioc) {
    if (!check_auth({"batch_detect"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    run_async_state<bool>(ioc, [batch, f=batch->detect()](bool& detected){ return f(detected); }, [send](auto ec, auto detected) mutable {
        return send(response::detectReturn(ec, detected));
    });
}

}

namespace cw {
namespace proxy {
namespace handler {

namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>

void ws(std::function<void(std::string)> send_, boost::asio::io_context& ioc, std::string input, std::set<std::string>& scopes, std::string& user, boost::optional<System>& selectedSystem) {
    cw::helper::uri::Uri url;

    rapidjson::Document indocument;
    indocument.Parse(input);
    if (indocument.HasParseError()) {
        return send_(jsonToString(response::validationError("input is not json").first));
    }
    if (!indocument.IsObject()) {
        return send_(jsonToString(response::validationError("input is not an object").first));
    }

    std::string tag;
    if (indocument.HasMember("tag")) {
        if (!indocument["tag"].IsString()) return send_(jsonToString(response::validationError("tag is not a string").first));
        tag = indocument["tag"].GetString();
        if (tag.empty()) return send_(jsonToString(response::validationError("tag is an empty string").first));
    }

    // note capture send functor by copy to ensure tag's lifetime
    auto send = [send_, tag](response::resp r) {
        if (!tag.empty()) r.first.AddMember("tag", tag, r.first.GetAllocator());
        send_(jsonToString(r.first));
    };
    
    if (!indocument.HasMember("command")) return send(response::json_error("CommandError", "command not given", http::status::bad_request)); 
    if (!indocument["command"].IsString()) return send(response::json_error("CommandError", "command is not a string", http::status::bad_request));
    std::string command = indocument["command"].GetString();

    auto check_auth =
    [send, &scopes](std::initializer_list<std::string> scopes_)
    {
        for (const auto& scope : scopes_) {
            if (!scopes.count(scope)) {
                send(response::invalid_auth(scope));
                return false;
            }
        }
        return true;
    };

    auto exec_callback = [&ioc, lifetime=send](cw::batch::Result& result, const cw::batch::Cmd& cmd) { cw::proxy::batch::runCommand(ioc, result, cmd); };

    if (command == "login") {
        return send(ws_login(scopes, user, indocument));
    } else if (command == "logout") {
        scopes.clear();
        user = "";
        return send(response::commandSuccess());
    } else if (command == "setBatchsystem") {
        return send(ws_setBatchsystem(selectedSystem, indocument));
    } else if (command == "detect") {
        f_detect(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "getBatchInfo") {
        f_getBatchInfo(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "getNodes") {
        f_getNodes(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "getQueues") {
        f_getQueues(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "getJobs") {
        f_getJobs(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "usersAdd") {
        f_usersAdd(check_auth, send, indocument, ioc);
    } else if (command == "usersDelete") {
        f_usersDelete(check_auth, send, indocument, url, ioc, &user, &scopes);
    } else if (command == "jobsSubmit") {
        f_jobsSubmit(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "jobsDeleteById") {
        f_jobsDeleteById(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "jobsDeleteByUser") {
        f_jobsDeleteByUser(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "changeNodeState") {
        f_changeNodeState(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "setQueueState") {
        f_setQueueState(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "setNodeComment") {
        f_setNodeComment(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "holdJob") {
        f_holdJob(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "releaseJob") {
        f_releaseJob(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "suspendJob") {
        f_suspendJob(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "resumeJob") {
        f_resumeJob(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else if (command == "rescheduleRunningJobInQueue") {
        f_rescheduleRunningJobInQueue(check_auth, send, indocument, url, exec_callback, selectedSystem, ioc);
    } else {
        send(response::commandUnknown(command));
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
            if (cw::globals::creds_check(user, pass, scopes)) {
                return true;
            }
        }
        to_response(res, response::invalid_auth());
        send_(std::move(res));
        return false;
    };

    auto check_json = 
    [send_, res, &content_type, &req](rapidjson::Document& document) mutable
    {
        if (content_type != "application/json") {
            res.result(http::status::unsupported_media_type);
            send_(std::move(res));
            return false;
        }

        document.Parse(req.body());
        if (document.HasParseError()) {
            res.result(http::status::unsupported_media_type);
            send_(std::move(res));
            return false;
        }

        return true;
    };

    auto exec_callback = [&ioc, lifetime=send](cw::batch::Result& result, const cw::batch::Cmd& cmd) { cw::proxy::batch::runCommand(ioc, result, cmd); };

    auto send_info = [send_, res](auto ec, auto container) mutable {
        to_response(res, response::containerReturn(ec, container));
        return send_(std::move(res));
    };

    auto send = [res, send_](response::resp r) mutable {
        to_response(res, r);
        return send_(std::move(res));
    };

    rapidjson::Document indocument;

    cw::helper::uri::Uri url;
    if (!cw::helper::uri::Uri::parse(url, std::string(req.target()))) return send(response::json_error("InvalidURI", "Error parsing URI", http::status::bad_request));

    if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "openapi.json") {
        api_openapi(res);
        return send_(std::move(res));
    } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "state") {
        f_detect(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "batchinfo") {
        f_getBatchInfo(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "nodes") {
        f_getNodes(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "queues") {
        f_getQueues(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "jobs") {
        f_getJobs(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 1 && url.path[0] == "users") {
        if (!check_json(indocument)) return;
        f_usersAdd(check_auth, send, indocument, ioc);
    } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "users") {
        f_usersDelete(check_auth, send, indocument, url, ioc, nullptr, nullptr);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[1] == "*" && url.path[2] == "submit") {
        if (!check_json(indocument)) return;
        f_jobsSubmit(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "jobs" && url.path[1] == "*") {
        f_jobsDeleteByUser(check_auth, send, indocument, url, exec_callback, {}, ioc);
    } else if (req.method() == http::verb::delete_ && url.path.size() == 2 && url.path[0] == "jobs") {
        f_jobsDeleteById(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "nodes" && url.path[2] == "state") {
        if (!check_json(indocument)) return;
        f_changeNodeState(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "queues" && url.path[2] == "state") {
        if (!check_json(indocument)) return;
        f_setQueueState(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "nodes" && url.path[2] == "comment") {
        if (!check_json(indocument)) return;
        f_setNodeComment(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "hold") {
        if (!check_json(indocument)) return;
        f_holdJob(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "release") {
        if (!check_json(indocument)) return;
        f_releaseJob(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "suspend") {
        if (!check_json(indocument)) return;
        f_suspendJob(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "resume") {
        if (!check_json(indocument)) return;
        f_resumeJob(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else if (req.method() == http::verb::post && url.path.size() == 3 && url.path[0] == "jobs" && url.path[2] == "reschedule") {
        if (!check_json(indocument)) return;
        f_rescheduleRunningJobInQueue(check_auth, send, indocument, url.remove_prefix(1), exec_callback, {}, ioc);
    } else {
        return send(response::requestUnknown(std::string(req.target()), req.method()));
    }
}

}
}
}
