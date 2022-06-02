/**
 * @file main.cpp
 * @brief Proxy
 *
 * ./src/proxy/proxy --cred ../data/creds run --cert ../data/server.crt --priv ../data/server.key --dh ../data/dh2048.pem --port 2000 --host 0.0.0.0
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
#include "proxy/globals.h"
#include "proxy/json.h"
#include "proxy/server.h"
#include "shared/obfuscator.h"
#include "shared/stream_cast.h"
#include "shared/sha512.h"
#include "proxy/salt_hash.h"
#include "proxy/set_echo.h"
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
namespace bp = boost::process;

namespace batch = cw::batch;

namespace {

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

struct CmdProcess {
    int exit;
    std::future<std::string> out; // before cp else "std::future_error: No associated state" because initialized afterwards
    std::future<std::string> err; // before cp else "std::future_error: No associated state" because initialized afterwards
    boost::optional<bp::child> cp;
};

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
    ioc_.post(cw::helper::y_combinator([asyncF, callbackF, &ioc_](auto handler){
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
void run_async_vector(boost::asio::io_context& ioc_, AsyncF asyncF, CallbackF callbackF) {
    ioc_.post(cw::helper::y_combinator_shared([container=std::vector<T>{}, asyncF, callbackF, &ioc_](auto handler) mutable {
        try {
            bool done = asyncF([&container](auto n) { container.push_back(std::move(n)); return true; });
            if (done) {
                callbackF(std::move(container), boost::system::error_code());
                return;
            }
        } catch (const boost::process::process_error& e) {
            callbackF(std::move(container), e.code());
            return;
        }
        ioc_.post(handler);
    }));
}

auto usersAdd(rapidjson::Document& document) {
    if (!document.HasMember("user")) throw std::runtime_error("user is not given");
    auto& user = document["user"];
    if (!user.IsString()) throw std::runtime_error("user is not a string");

    if (!document.HasMember("password")) throw std::runtime_error("password is not given");
    auto& password = document["password"];
    if (!password.IsString()) throw std::runtime_error("password is not a string");

    std::set<std::string> scopesset;
    if (document.HasMember("scopes")) {
        auto& scopes = document["scopes"];
        if (!scopes.IsArray()) throw std::runtime_error("scopes is not an array");
        for (const auto& v : scopes.GetArray()) {
            if (!v.IsString()) throw std::runtime_error("scopes array item is not an string");
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

http::response<http::string_body> api_openapi() {
    http::string_body::value_type body{cw::openapi::openapi_json};
    const auto size = body.size();
    // Respond to GET request
    http::response<http::string_body> res{
        std::piecewise_construct,
        std::make_tuple(std::move(body)),
        std::make_tuple(http::status::ok, 11)};
    res.set(http::field::content_type, "application/json");
    res.content_length(size);
    return res;
}

http::response<http::string_body> json_response(const rapidjson::Document& document, http::status status = http::status::ok) {
    http::response<http::string_body> res{status, 11};
    res.set(http::field::content_type, "application/json");
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    res.body() = buffer.GetString();
    res.prepare_payload();
    return res;
}

http::response<http::string_body> json_error_response(const std::string& type, const std::string& message, http::status status) {
    return json_response(cw::proxy::json::generate_json_error(type, message, status), status);
}

struct Handler {
    constexpr static std::chrono::duration<long int> timeout() { return std::chrono::seconds(30); }
    constexpr static unsigned int body_limit() { return 10000; }
    constexpr static unsigned int limit() { return 8; }


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

        auto const empty_response =
        [&](http::status status)
        {
            http::response<http::string_body> res{status, 11}; // req.version(); fails
            return res;
        };

        auto const bad_request =
        [&]()
        {
            return json_error_response("Bad request", "Unsupported API call", http::status::bad_request);
        };

        auto const check_auth =
        [&](const std::set<std::string>& scopes = {})
        {
            bool authed = cw::globals::creds_check(req[http::field::authorization], scopes);
            if (!authed) send(json_error_response("Invalid credentials or scope", "Could not authenticate user or user does not have requested scopes", http::status::unauthorized));
            return authed;
        };

        auto const check_json = 
        [&](rapidjson::Document& document)
        {
            if (content_type != "application/json") {
                send(empty_response(http::status::unsupported_media_type));
                return false;
            }

            document.Parse(req.body());
            if (document.HasParseError()) {
                send(empty_response(http::status::unsupported_media_type));
                return false;
            }

            return true;
        };



        auto const exec_callback = [&send, &ioc_](cw::batch::Result& res, const cw::batch::Cmd& cmd) {
            // start command
            std::shared_ptr<CmdProcess> process{new CmdProcess{}};
            process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > process->out, bp::std_err > process->err, ioc_, bp::on_exit=[process, &res, &send](int ret, const std::error_code& ec){
                res.exit = ec ? -2 : ret;
                if (ec) return send(json_error_response("Running command failed", "Could not run command", http::status::internal_server_error));
                if (ret != 0) return send(json_error_response("Running command failed", "Command exited with error code", http::status::internal_server_error));

                res.out = process->out.get();
                res.err = process->err.get();
            });
        };

        auto const send_info = [&send](auto container, auto ec){
            if (ec) {
                send(json_error_response("Running command failed", ec.message(), http::status::internal_server_error));
            } else {
                send(json_response(cw::helper::json::serialize_wrap(container)));
            }
        };
            
        if (req.method() == http::verb::get && req.target() == "/openapi.json") {
            auto res = api_openapi();
            res.version(req.version());
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.keep_alive(req.keep_alive());
            return send(std::move(res));
        } else if (req.method() == http::verb::get && req.target() == "/nodes") {
            if (!check_auth({"nodes_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_vector<cw::batch::Node>(ioc_, [batch, f=batch->getNodes(std::vector<std::string>{})](auto... args){ (void)batch; return f(args...); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/queues") {
            if (!check_auth({"queues_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_vector<cw::batch::Queue>(ioc_, [batch, f=batch->getQueues()](auto... args){ (void)batch; return f(args...); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/jobs") {
            if (!check_auth({"jobs_info"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            run_async_vector<cw::batch::Job>(ioc_, [batch, f=batch->getJobs(std::vector<std::string>{})](auto... args){ (void)batch; return f(args...); }, send_info);
            return;
        } else if (req.method() == http::verb::get && req.target() == "/jobs/delete") {
            if (!check_auth({"jobs_delete"})) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            auto f = batch->deleteJobById("id", false);
            run_async(ioc_, f, [&send, &empty_response](auto ec){
                if (ec) {
                    return send(json_error_response("Running command failed", ec.message(), http::status::internal_server_error));
                } else {
                    return send(empty_response(http::status::ok));
                }
            });
            return;
        } else if (req.method() == http::verb::post && req.target() == "/jobs/submit") {
            if (!check_auth({"jobs_submit"})) return;
            rapidjson::Document indocument;
            if (!check_json(indocument)) return;

            std::shared_ptr<cw::batch::BatchInterface> batch = create_batch(cw::batch::System::Pbs, exec_callback);
            std::function<cw::batch::runJob_f> f;
            try {
                f = cw_proxy_batch::runJob(*batch, indocument);
            } catch (const std::runtime_error& e) {
                return send(json_error_response("Request body validation failed", e.what(), http::status::internal_server_error));
            }
            ioc_.post(cw::helper::y_combinator([f, batch, &send, &ioc_](auto handler){
                try {
                    std::string jobName;
                    if (f(jobName)) {

                        rapidjson::Document document;
                        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
                        document.SetObject();
                        {
                            rapidjson::Value data;
                            data.SetObject();
                            data.AddMember("job", jobName, allocator);
                            document.AddMember("data", data, allocator);
                        }

                        send(json_response(document));
                    }
                } catch (const boost::process::process_error& e) {
                    auto ec = e.code();
                    return send(json_error_response("Running command failed", ec.message(), http::status::internal_server_error));
                }
                ioc_.post(handler);
            }));

            return;
        } else if (req.method() == http::verb::post && req.target() == "/users") {
            if (!check_auth({"users_add"})) return;
            auto stream = std::make_shared<boost::asio::posix::stream_descriptor>(ioc_, ::creat(cw::globals::cred_file().c_str(), 0755));

            rapidjson::Document indocument;
            if (!check_json(indocument)) return;

            try {
                auto f = usersAdd(indocument);

                auto creds = cw::globals::creds();
                f(creds);
                auto s = std::make_shared<std::string>();
                cw::helper::credentials::write(creds, *s);
                boost::asio::async_write(*stream, boost::asio::buffer(*s), boost::asio::transfer_all(), [stream, s, creds, &empty_response, &send](beast::error_code ec, size_t len){
                    (void)len;
                    if (ec) {
                        return send(json_error_response("Writing credentials failed", ec.message(), http::status::internal_server_error));
                    } else {
                        // store new credentials in global after successfull write
                        cw::globals::creds(creds);
                        return send(empty_response(http::status::created));
                    }
                });
            } catch (const std::runtime_error& e) {
                return send(json_error_response("Request body validation failed", e.what(), http::status::internal_server_error));
            }

            return;
        }
        return send(bad_request());
    }
};


int main_loop(const std::string& cred, int threads, const std::string& host, int port, const std::string& cert, const std::string& priv, const std::string& dh, bool force_ssl, bool no_ssl) {
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
        force_ssl)->run();

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

    auto cli = (
        (clipp::command("help").set(selected,mode::help) % "Show help message")
        | (((clipp::required("--cred") & clipp::value("CRED", cred)) % "Credentials file"),
            (clipp::command("run").set(selected, mode::run) % "Run server",
                (((clipp::option("--force-ssl").set(force_ssl)) % "Disable automatic HTTP/HTTPS detection and only support SSL")
                    |((clipp::option("--no-ssl").set(no_ssl)) % "Disable SSL encryption")),
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
        case mode::run: return main_loop(cred, threads, host, port, cert, priv, dh, force_ssl, no_ssl);
    }


    return 0;
}
