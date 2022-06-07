/**
 * @file main.cpp
 * @brief Proxy
 *
 * ./src/proxy/proxy --cred ../data/creds run --cert ../data/server.crt --priv ../data/server.key --dh ../data/dh2048.pem --port 2000 --host 0.0.0.0
 * wscat -n -c "wss://127.0.0.1:2000/"
 * curl --insecure -u "admin:admin" https://127.0.0.1:2000/nodes
 * curl --insecure -u "admin:admin" https://127.0.0.1:2000/users -H "Content-Type: application/json" -d '{"user": "e", "password": "a", "scopes": ["aa"]}'
 * 
 ***********************************************/

#include <signal.h>
#include <unistd.h>

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

#include <cassert>
#include <stdlib.h>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "proxy/openapi_json.h"
#include "proxy/credentials.h"
#include "proxy/batchsystem_json.h"
#include "proxy/batchsystem_process.h"
#include "proxy/globals.h"
#include "proxy/json.h"
#include "proxy/server.h"
#include "shared/obfuscator.h"
#include "shared/stream_cast.h"
#include "shared/sha512.h"
#include "proxy/salt_hash.h"
#include "proxy/set_echo.h"
#include "proxy/validation.h"
#include "proxy/y_combinator.h"
#include "shared/string_view.h"
#include "shared/batch_json.h"


#include "clipp.h"

#include "batchsystem/batchsystem.h"
#include "batchsystem/factory.h"

namespace defaults {

constexpr int port = 2000;
constexpr const char* host = "0.0.0.0";
constexpr unsigned int threads = 10;
constexpr const char* cred = "/etc/trex/creds";
constexpr const char* cert = "/etc/trex/server.crt";
constexpr const char* priv = "/etc/trex/server.key";
constexpr const char* dh = "/etc/trex/dh2048.pem";
constexpr const char* password_prompt = "password> ";

}

namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>

namespace batch = cw::batch;

namespace {

std::string jsonToString(const rapidjson::Document& document) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    return buffer.GetString();
} 

std::string prompt(const std::string& prefix) {
    if (!prefix.empty()) {
        std::cout << prefix;
        std::cout.flush();
    }
    cw::helper::set_echo(false);
    std::string input;
    std::getline(std::cin, input);
    cw::helper::set_echo(true);
    return input;
}

}

void set_ssl_context(ssl::context& ctx, const std::string& cert, const std::string& priv, const std::string& dh) {
    // The SSL context is required, and holds certificates
    ctx.set_options(
        boost::asio::ssl::context::default_workarounds
        | boost::asio::ssl::context::no_sslv2
        | boost::asio::ssl::context::single_dh_use);
    ctx.use_certificate_chain_file(cert);
    ctx.use_private_key_file(priv, boost::asio::ssl::context::pem);
    ctx.use_tmp_dh_file(dh);
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

auto usersAdd(rapidjson::Document& document) {
    if (!document.HasMember("user")) throw cw::helper::ValidationError("user is not given");
    auto& user = document["user"];
    if (!user.IsString()) throw cw::helper::ValidationError("user is not a string");

    if (!document.HasMember("password")) throw cw::helper::ValidationError("password is not given");
    auto& password = document["password"];
    if (!password.IsString()) throw cw::helper::ValidationError("password is not a string");

    std::set<std::string> scopesset;
    if (document.HasMember("scopes")) {
        auto& scopes = document["scopes"];
        if (!scopes.IsArray()) throw cw::helper::ValidationError("scopes is not an array");
        for (const auto& v : scopes.GetArray()) {
            if (!v.IsString()) throw cw::helper::ValidationError("scopes array item is not an string");
            scopesset.insert(v.GetString());
        }
    }

    return [user=user.GetString(), password=password.GetString(), scopes=std::move(scopesset)](cw::helper::credentials::dict& creds){
        cw::helper::credentials::set_user(creds, user, scopes, password);
    };
}

bool read_cred(const std::string& cred_file, cw::helper::credentials::dict& creds) {
    std::ifstream creds_fs(cred_file);
    if (!creds_fs.good()) {
        std::cout << "Could not open '" << cred_file << "' for reading" << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << creds_fs.rdbuf();

    cw::helper::credentials::read(creds, buffer.str());
    return true;
}

bool write_cred(const std::string& cred_file, const cw::helper::credentials::dict& creds) {
    std::ofstream creds_fso(cred_file);
    if (!creds_fso.good()) {
        std::cout << "Could not open '" << cred_file << "' for writing" << std::endl;
        return false;
    }

    std::string out;
    cw::helper::credentials::write(creds, out);
    creds_fso << out;
    return true;
}

int user_set(const std::string& cred_file, const std::string& username, const std::vector<std::string>& scopes) {
    cw::helper::credentials::dict creds;
    if (!read_cred(cred_file, creds)) return 1;
    
    std::set<std::string> scopes_set(scopes.begin(), scopes.end());
    cw::helper::credentials::set_user(creds, username, scopes_set, prompt(defaults::password_prompt));

    if (!write_cred(cred_file, creds)) return 1;
    return 0;
}

int user_remove(const std::string& cred_file, const std::string& username) {
    cw::helper::credentials::dict creds;
    if (!read_cred(cred_file, creds)) return 1;

    auto it = creds.find(username);
    if (it == creds.end()) {
        std::cout << "Username '" << username << "' not found" << std::endl;
        return 1;
    }
    creds.erase(it);
    
    if (!write_cred(cred_file, creds)) return 1;
    return 0;
}

void api_openapi(http::response<http::string_body>& res) {
    res.result(http::status::ok);
    res.set(http::field::content_type, "application/json");
    res.body() = cw::openapi::openapi_json;
    res.prepare_payload();
}

void json_response(http::response<http::string_body>& res, const rapidjson::Document& document, http::status status = http::status::ok) {
    res.result(status);
    res.set(http::field::content_type, "application/json");
    res.body() = jsonToString(document);
    res.prepare_payload();
}

void json_error_response(http::response<http::string_body>& res, const std::string& type, const std::string& message, http::status status) {
    json_response(res, cw::proxy::json::generate_json_error(type, message, status), status);
}

void bad_request(http::response<http::string_body>& res) {
    json_error_response(res, "Bad request", "Unsupported API call", http::status::bad_request);
}

void json_error_response_ec(http::response<http::string_body>& res, std::error_code ec, const std::string& type = "Running command failed") {
    json_error_response(res, type, ec.message(), http::status::internal_server_error);
}

void json_error_response_exc(http::response<http::string_body>& res, const std::exception& e, const std::string& type = "Exception thrown") {
    json_error_response(res, type, e.what(), http::status::internal_server_error);
}
void json_error_response_exc(http::response<http::string_body>& res, const cw::helper::ValidationError& e, const std::string& type = "Request body validation failed") {
    json_error_response(res, type, e.what(), http::status::bad_request);
}


void invalid_auth(http::response<http::string_body>& res) {
    json_error_response(res, "Invalid credentials or scope", "Could not authenticate user or user does not have requested scopes", http::status::unauthorized);
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

struct Handler {
    constexpr static std::chrono::duration<long int> timeout() { return std::chrono::seconds(30); }
    constexpr static unsigned int body_limit() { return 10000; }
    constexpr static unsigned int limit() { return 8; }

    struct websocket_session {
        std::set<std::string> scopes;
    };

    template <class Session, class Send>
    static void handle_socket(Session& self, std::string input, Send&& send) {
        self.scopes.insert("abc");
        rapidjson::Document indocument;
        indocument.Parse(input);
        if (indocument.HasParseError()) {
            return send(jsonToString(cw::proxy::json::generate_json_error("InvalidInput", "Input not json", http::status::internal_server_error)));
        }

        std::string tag;
        if (indocument.HasMember("tag") && indocument["tag"].IsString()) tag = indocument["tag"].GetString();
        
        std::string command;
        if (indocument.HasMember("command") && indocument["command"].IsString()) command = indocument["command"].GetString();

        if (!command.empty()) {
            if (command == "login") {
                if (!(indocument.HasMember("user") && indocument["user"].IsString())) throw cw::helper::ValidationError("user invalid");
                if (!(indocument.HasMember("password") && indocument["password"].IsString())) throw cw::helper::ValidationError("password invalid");
                if (cw::globals::creds_get(indocument["user"].GetString(), indocument["password"].GetString(), self.scopes)) {

                } else {
                    return send(jsonToString(cw::proxy::json::generate_json_error("LoginFailed", "LoginFailed", http::status::internal_server_error)));
                }
            } else if (command == "a") {
                if (!self.scopes.count("nodes_info")) return send(jsonToString(cw::proxy::json::generate_json_error("AuthError", "scopes missing", http::status::internal_server_error)));
            }
        }


        rapidjson::Document document;
        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
        document.SetObject();
        if (!tag.empty()) {
            document.AddMember("tag", tag, allocator);
        }
        send(jsonToString(document));
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template< 
        class Body, class Allocator,
        class Send>
    static void
    handle_request(
        boost::asio::io_context& ioc_,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send&& send
        )
    {
        auto content_type = req[http::field::content_type];

        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.keep_alive(req.keep_alive());

        auto check_auth =
        [&send, &res, &req](const std::set<std::string>& scopes = {}) mutable
        {
            std::string user, pass;
            if (cw::http::parse_auth_header(req[http::field::authorization], user, pass)) {
                if (cw::globals::creds_check(user, pass, scopes)) {
                    return true;
                }
            }
            invalid_auth(res);
            send(std::move(res));
            return false;
        };

        auto check_json = 
        [&send, res, &content_type, &req](rapidjson::Document& document) mutable
        {
            if (content_type != "application/json") {
                res.result(http::status::unsupported_media_type);
                send(std::move(res));
                return false;
            }

            document.Parse(req.body());
            if (document.HasParseError()) {
                res.result(http::status::unsupported_media_type);
                send(std::move(res));
                return false;
            }

            return true;
        };

        auto exec_callback = [&ioc_](cw::batch::Result& result, const cw::batch::Cmd& cmd) { cw::proxy::batch::runCommand(ioc_, result, cmd); };

        auto send_info = [&send, res](auto ec, auto container) mutable {
            if (ec) {
                json_error_response_ec(res, ec);
                send(std::move(res));
            } else {
                json_response(res, cw::helper::json::serialize_wrap(container));
                send(std::move(res));
            }
        };
            
        if (req.method() == http::verb::get && req.target() == "/openapi.json") {
            api_openapi(res);
            return send(std::move(res));
        } else if (req.method() == http::verb::get && req.target() == "/nodes") {
            if (!check_auth({"nodes_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_state<std::vector<cw::batch::Node>>(ioc_, [batch, f=batch->getNodes(std::vector<std::string>{})](std::vector<cw::batch::Node>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/queues") {
            if (!check_auth({"queues_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_state<std::vector<cw::batch::Queue>>(ioc_, [batch, f=batch->getQueues()](std::vector<cw::batch::Queue>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/jobs") {
            if (!check_auth({"jobs_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_state<std::vector<cw::batch::Job>>(ioc_, [batch, f=batch->getJobs(std::vector<std::string>{})](std::vector<cw::batch::Job>& state){ return f([&state](auto n) { state.push_back(std::move(n)); return true; }); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/jobs/delete") {
            if (!check_auth({"jobs_delete"})) return;
            rapidjson::Document indocument;
            if (!check_json(indocument)) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            try {
                auto f = cw_proxy_batch::deleteJobById(*batch, indocument);
                run_async(ioc_, f, [batch, &send, res](auto ec) mutable {
                    if (ec) {
                        json_error_response_ec(res, ec);
                        return send(std::move(res));
                    } else {
                        res.result(http::status::ok);
                        return send(std::move(res));
                    }
                });
            } catch (const cw::helper::ValidationError& e) {
                json_error_response_exc(res, e);
                return send(std::move(res));
            }
            return;
        } else if (req.method() == http::verb::post && req.target() == "/jobs/submit") {
            if (!check_auth({"jobs_submit"})) return;
            rapidjson::Document indocument;
            if (!check_json(indocument)) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            try {
                auto f = cw_proxy_batch::runJob(*batch, indocument);

                run_async_state<std::string>(ioc_, f, [batch, &send, res](auto ec, std::string jobName) mutable {
                    if (ec) {
                        json_error_response_ec(res, ec);
                        return send(std::move(res));
                    } else {
                        rapidjson::Document document;
                        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
                        document.SetObject();
                        {
                            rapidjson::Value data;
                            data.SetObject();
                            data.AddMember("job", jobName, allocator);
                            document.AddMember("data", data, allocator);
                        }

                        json_response(res, document);
                        send(std::move(res));
                    }
                });
                return;
            } catch (const cw::helper::ValidationError& e) {
                json_error_response_exc(res, e);
                return send(std::move(res));
            }
            return;
        } else if (req.method() == http::verb::post && req.target() == "/users") {
            if (!check_auth({"users_add"})) return;

            rapidjson::Document indocument;
            if (!check_json(indocument)) return;

            try {
                auto f = usersAdd(indocument);


                auto creds = cw::globals::creds();
                f(creds);
                write_creds_async(ioc_, creds, [res,&send](auto ec) mutable {
                    if (ec) {
                        json_error_response_ec(res, ec, "Writing credentials failed");
                        return send(std::move(res));
                    } else {
                        res.result(http::status::created);
                        return send(std::move(res));
                    }

                });
            } catch (const cw::helper::ValidationError& e) {
                json_error_response_exc(res, e);
                return send(std::move(res));
            }

            return;
        }
        bad_request(res);
        return send(std::move(res));
    }
};


int main_loop(const std::string& cred, int threads, const std::string& host, int port, const std::string& cert, const std::string& priv, const std::string& dh, bool force_ssl, bool no_ssl, bool no_websocket) {
    if (threads < 1) {
        std::cout << "Minimum 1 thread" << std::endl;
        return 1;
    }

    if (port < 1 || port > 65535) {
        std::cout << "Invalid PORT (1-65535) " << port << std::endl;
        return 1;
    }

    // The io_context is required for all I/O
    net::io_context ioc{static_cast<int>(threads)};

    // Capture SIGINT and SIGTERM to perform a clean shutdown
    net::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
    [&](beast::error_code const&, int)
    {
        // Stop the `io_context`. This will cause `run()`
        // to return immediately, eventually destroying the
        // `io_context` and all of the sockets in it.
        ioc.stop();
    });

    auto const address = net::ip::make_address(host);

    ssl::context ctx{boost::asio::ssl::context::sslv23};
    if (!no_ssl) set_ssl_context(ctx, cert, priv, dh);

    cw::helper::credentials::dict creds;
    if (!read_cred(cred, creds)) return 1;
    cw::globals::init(creds, cred);

    // Create and launch a listening port
    std::make_shared<cw::proxy::listener<Handler>>(
        ioc,
        ctx,
        tcp::endpoint{address, static_cast<unsigned short>(port)},
        force_ssl,
        !no_websocket)->run();

    std::cout << "Server running" << std::endl;

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc]
        {
            ioc.run();
        });
    ioc.run();

    // (If we get here, it means we got a SIGINT or SIGTERM)

    // Block until all the threads exit
    for(auto& t : v)
        t.join();

    return 0;
}

int main(int argc, char **argv) {
    enum class mode { run, user_set, user_remove, help };
    mode selected;

    std::string cert = defaults::cert;
    std::string cred = defaults::cred;
    std::string dh = defaults::dh;
    std::string priv = defaults::priv;
    std::string host = defaults::host;
    int port = defaults::port;
    std::string username;
    unsigned int threads = defaults::threads;
    std::vector<std::string> scopes;
    bool no_ssl = false;
    bool force_ssl = false;
    bool no_websocket = false;

    auto cli = (
        (clipp::command("help").set(selected,mode::help) % "Show help message")
        | (((clipp::required("--cred") & clipp::value("CRED", cred)) % "Credentials file"),
            (clipp::command("run").set(selected, mode::run) % "Run server",
                (((clipp::option("--force-ssl").set(force_ssl)) % "Disable automatic HTTP/HTTPS detection and only support SSL")
                    |((clipp::option("--no-ssl").set(no_ssl)) % "Disable SSL encryption")),
                (clipp::option("--no-ws").set(no_websocket)) % "Disable websocket support",
                (clipp::option("--cert") & clipp::value("CERT", cert)) % "SSL certificate file",
                (clipp::option("--priv") & clipp::value("KEY", priv)) % "SSL private key file",
                (clipp::option("--dh") & clipp::value("DH", dh)) % "SSL dh file",
                (clipp::option("--port") & clipp::value("PORT", port)) % "Port to run server on (1-65535), default 80",
                (clipp::option("--host") & clipp::value("HOST", host)) % "Host to run server on, default 0.0.0.0",
                (clipp::option("--threads") & clipp::value("NTHREADS", threads)) % "Number of threads to use"
            )
            | (clipp::command("user"), ((clipp::command("set").set(selected, mode::user_set) % "Set / add user credentials",
                (clipp::value("name").set(username)) % "Username",
                (clipp::option("--scopes") & clipp::values("SCOPE", scopes)) % "Permission scopes to set for user"
            ) | (clipp::command("remove").set(selected, mode::user_remove) % "Remove user credentials",
                (clipp::value("name").set(username)) % "Username"
            ))))
    );

    if (!clipp::parse(argc, argv, cli)) selected = mode::help;

    switch (selected) {
        default: {
            assert(false && "invalid cmd");
            return 1;
        }
        case mode::help: {
            // std::cout << make_man_page(cli, argv[0]) << std::endl;
            std::cout << "USAGE:\n"
                    << clipp::usage_lines(cli, argv[0]) << "\n\n\n"
                    << "PARAMETERS:\n\n"
                    << clipp::documentation(cli) << std::endl;
            return 1;
        }
        case mode::user_set: return user_set(cred, username, scopes);
        case mode::user_remove: return user_remove(cred, username);
        case mode::run: return main_loop(cred, threads, host, port, cert, priv, dh, force_ssl, no_ssl, no_websocket);
    }


    return 0;
}
