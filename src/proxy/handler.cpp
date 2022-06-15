#include "proxy/handler.h"
#include "proxy/server.h"

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
#include <boost/optional.hpp>
#include <boost/process.hpp>
#include <boost/asio/error.hpp>

#include "batchsystem/batchsystem.h"
#include "batchsystem/factory.h"


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
            if (!parseSystem(sys, document["batchsystem"].GetString())) system = sys;
        }
    }
    if (document.HasMember("batchsystem") && document["batchsystem"].IsString()) {
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

response::resp ws_login(std::set<std::string>& scopes, const rapidjson::Document& indocument) {
    if (!(indocument.HasMember("user") && indocument["user"].IsString())) return response::validationError("user invalid");
    if (!(indocument.HasMember("password") && indocument["password"].IsString())) return response::validationError("password invalid");
    if (cw::globals::creds_get(indocument["user"].GetString(), indocument["password"].GetString(), scopes)) {
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

template <typename Session, typename CheckAuth, typename Send>
auto f_usersAdd(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument) {
    if (!check_auth({"users_add"})) return;

    std::string err;
    auto o = cw_proxy_batch::usersAdd(indocument, "", err);
    if (!o) return send(response::validationError(err));

    auto creds = cw::globals::creds();
    nonstd::apply([&creds](auto&&... args){cw::helper::credentials::set_user(creds, args...);}, std::move(*o));
    write_creds_async(session->ioc(), creds, [send](auto ec) mutable {
        return send(response::addUserReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_jobsSubmit(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_submit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->runJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::runJob(indocument, err);
    if (!o) return send(response::validationError(err));
    auto f = batch->runJob(*o);

    run_async_state<std::string>(session->ioc(), f, [batch, send](auto ec, std::string jobName) mutable {
        return send(response::runJobReturn(ec, jobName));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_jobsDeleteById(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_delete"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->deleteJobById(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::deleteJobById(indocument, uri, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->deleteJobById(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_jobsDeleteByUser(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_user_delete"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->deleteJobByUser(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::deleteJobByUser(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->deleteJobByUser(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_changeNodeState(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"nodes_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->changeNodeState(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::changeNodeState(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->changeNodeState(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_setQueueState(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"queues_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->setQueueState(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::setQueueState(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->setQueueState(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_setNodeComment(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"nodes_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->setNodeComment(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::setNodeComment(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->setNodeComment(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_holdJob(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->holdJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::holdJob(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->holdJob(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_releaseJob(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->releaseJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::releaseJob(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->releaseJob(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_suspendJob(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->suspendJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::suspendJob(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->suspendJob(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_resumeJob(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->resumeJob(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::resumeJob(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->resumeJob(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_rescheduleRunningJobInQueue(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_edit"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->rescheduleRunningJobInQueue(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::rescheduleRunningJobInQueue(indocument, err);
    if (!o) return send(response::validationError(err));

    auto f = nonstd::apply([batch](auto&&... args){ return batch->rescheduleRunningJobInQueue(args...); }, std::move(*o));
    run_async(session->ioc(), f, [batch, send](auto ec) mutable {
        return send(response::commandReturn(ec));
    });
}


template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_getJobs(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"jobs_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getJobs(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::getJobs(indocument, err);
    if (!err.empty()) return send(response::validationError(err));

    run_async_state<std::vector<cw::batch::Job>>(session->ioc(), [batch, f=batch->getJobs(o)](std::vector<cw::batch::Job>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_getQueues(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"queues_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getQueues(supported)) return send(response::commandUnsupported());

    run_async_state<std::vector<cw::batch::Queue>>(session->ioc(), [batch, f=batch->getQueues()](std::vector<cw::batch::Queue>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_getNodes(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"nodes_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getNodes(supported)) return send(response::commandUnsupported());

    std::string err;
    auto o = cw_proxy_batch::getNodes(indocument, uri, err);
    if (!err.empty()) return send(response::validationError(err));

    run_async_state<std::vector<cw::batch::Node>>(session->ioc(), [batch, f=batch->getNodes(o)](std::vector<cw::batch::Node>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, [send](auto ec, auto container) mutable {
        return send(response::containerReturn(ec, container));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_getBatchInfo(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"batch_info"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    if (!batch->getBatchInfo(supported)) return send(response::commandUnsupported());

    run_async_state<BatchInfo>(session->ioc(), [batch, f=batch->getBatchInfo()](BatchInfo& state){ return f(state); }, [send](auto ec, auto batchinfo) mutable {
        return send(response::getBatchInfoReturn(ec, batchinfo));
    });
}

template <typename Session, typename CheckAuth, typename Send, typename ExecCb>
void f_detect(Session session, CheckAuth check_auth, Send send, const rapidjson::Document& indocument, const Uri& uri, ExecCb exec_cb, const boost::optional<System>& system) {
    if (!check_auth({"detect"})) return;

    auto batch = getBatch(indocument, uri, exec_cb, system);
    if (!batch) return send(response::invalidBatch());

    run_async_state<bool>(session->ioc(), [batch, f=batch->detect()](bool& detected){ return f(detected); }, [send](auto ec, auto detected) mutable {
        return send(response::detectReturn(ec, detected));
    });
}


struct Handler {
    constexpr static std::chrono::duration<long int> timeout() { return std::chrono::seconds(30); }
    constexpr static unsigned int body_limit() { return 10000; }
    constexpr static unsigned int limit() { return 8; }

    struct websocket_session {
        std::set<std::string> scopes;
        boost::optional<System> selectedSystem;
    };

    template <class Session>
    static void handle_socket(std::shared_ptr<Session> session, std::string input) {
        cw::helper::uri::Uri url;

        rapidjson::Document indocument;
        indocument.Parse(input);
        if (indocument.HasParseError()) {
            return session->send(jsonToString(response::validationError("input is not json").first));
        }
        if (!indocument.IsObject()) {
            return session->send(jsonToString(response::validationError("input is not an object").first));
        }

        std::string tag;
        if (indocument.HasMember("tag")) {
            if (!indocument["tag"].IsString()) return session->send(jsonToString(response::validationError("tag is not a string").first));
            tag = indocument["tag"].GetString();
            if (tag.empty()) return session->send(jsonToString(response::validationError("tag is an empty string").first));
        }

        // note capture send functor by copy to ensure tag's lifetime
        auto send = [session, tag](response::resp r) {
            if (!tag.empty()) r.first.AddMember("tag", tag, r.first.GetAllocator());
            session->send(jsonToString(r.first));
        };
        
        if (!indocument.HasMember("command")) return send(response::json_error("CommandError", "command not given", http::status::bad_request)); 
        if (!indocument["command"].IsString()) return send(response::json_error("CommandError", "command is not a string", http::status::bad_request));
        std::string command = indocument["command"].GetString();

        auto check_auth =
        [session, send](std::initializer_list<std::string> scopes)
        {
            for (const auto& scope : scopes) {
                if (!session->scopes.count(scope)) {
                    send(response::invalid_auth(scope));
                    return false;
                }
            }
            return true;
        };

        auto exec_callback = [session](cw::batch::Result& result, const cw::batch::Cmd& cmd) { cw::proxy::batch::runCommand(session->ioc(), result, cmd); };

        if (command == "login") {
            return send(ws_login(session->scopes, indocument));
        } else if (command == "logout") {
            session->scopes.clear();
            return send(response::commandSuccess());
        } else if (command == "setBatchsystem") {
            return send(ws_setBatchsystem(session->selectedSystem, indocument));
        } else if (command == "detect") {
            f_detect(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "getBatchInfo") {
            f_getBatchInfo(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "getNodes") {
            f_getNodes(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "getQueues") {
            f_getQueues(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "getJobs") {
            f_getJobs(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "addUser") {
            f_usersAdd(session, check_auth, send, indocument);
        } else if (command == "jobsSubmit") {
            f_jobsSubmit(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "jobsDeleteById") {
            f_jobsDeleteById(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "jobsDeleteByUser") {
            f_jobsDeleteByUser(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "changeNodeState") {
            f_changeNodeState(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "setQueueState") {
            f_setQueueState(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "setNodeComment") {
            f_setNodeComment(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "holdJob") {
            f_holdJob(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "releaseJob") {
            f_releaseJob(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "suspendJob") {
            f_suspendJob(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "resumeJob") {
            f_resumeJob(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else if (command == "rescheduleRunningJobInQueue") {
            f_rescheduleRunningJobInQueue(session, check_auth, send, indocument, url, exec_callback, session->selectedSystem);
        } else {
            send(response::commandUnknown(command));
        }
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template< class Session,
        class Body, class Allocator>
    static void
    handle_request(
        std::shared_ptr<Session> session,
        http::request<Body, http::basic_fields<Allocator>>&& req
        )
    {
        auto content_type = req[http::field::content_type];

        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.keep_alive(req.keep_alive());

        auto check_auth =
        [session, &res, &req](const std::set<std::string>& scopes = {}) mutable
        {
            std::string user, pass;
            if (cw::http::parse_auth_header(req[http::field::authorization], user, pass)) {
                if (cw::globals::creds_check(user, pass, scopes)) {
                    return true;
                }
            }
            to_response(res, response::invalid_auth());
            session->send(std::move(res));
            return false;
        };

        auto check_json = 
        [session, res, &content_type, &req](rapidjson::Document& document) mutable
        {
            if (content_type != "application/json") {
                res.result(http::status::unsupported_media_type);
                session->send(std::move(res));
                return false;
            }

            document.Parse(req.body());
            if (document.HasParseError()) {
                res.result(http::status::unsupported_media_type);
                session->send(std::move(res));
                return false;
            }

            return true;
        };

        auto exec_callback = [session](cw::batch::Result& result, const cw::batch::Cmd& cmd) { cw::proxy::batch::runCommand(session->ioc(), result, cmd); };

        auto send_info = [session, res](auto ec, auto container) mutable {
            to_response(res, response::containerReturn(ec, container));
            return session->send(std::move(res));
        };

        auto send = [res, session](response::resp r) mutable {
            to_response(res, r);
            return session->send(std::move(res));
        };

        rapidjson::Document indocument;

        cw::helper::uri::Uri url;
        if (!cw::helper::uri::Uri::parse(url, std::string(req.target()))) return send(response::json_error("InvalidURI", "Error parsing URI", http::status::bad_request));

        if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "openapi.json") {
            api_openapi(res);
            return session->send(std::move(res));
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "nodes") {
            f_getNodes(session, check_auth, send, indocument, url, exec_callback, {});
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "queues") {
            f_getQueues(session, check_auth, send, indocument, url, exec_callback, {});
        } else if (req.method() == http::verb::get && url.path.size() == 1 && url.path[0] == "jobs") {
            f_getJobs(session, check_auth, send, indocument, url, exec_callback, {});
        } else if (req.method() == http::verb::post && url.path.size() == 1 && url.path[0] == "jobs") {
            if (!check_json(indocument)) return;
            f_jobsSubmit(session, check_auth, send, indocument, url, exec_callback, {});
        } else if (req.method() == http::verb::post && url.path.size() == 1 && url.path[0] == "users") {
            if (!check_json(indocument)) return;
            f_usersAdd(session, check_auth, send, indocument);
        } else if (req.method() == http::verb::delete_ && url.path.size() == 1 && url.path[0] == "jobs") {
            url.path.erase(url.path.begin());
            f_jobsDeleteById(session, check_auth, send, indocument, url, exec_callback, {});
        } else {
            return send(response::requestUnknown(std::string(req.target()), req.method()));
        }
    }


};

}

namespace cw {
namespace proxy {

void run(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx, boost::asio::ip::tcp::endpoint endpoint, bool force_ssl, bool websocket_support) {
    std::make_shared<cw::proxy::listener<Handler>>(
        ioc,
        ctx,
        endpoint,
        force_ssl,
        websocket_support)->run();
}

}
}
