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

#include "shared/obfuscator.h"
#include "shared/stream_cast.h"
#include "shared/sha512.h"
#include "proxy/salt_hash.h"
#include "proxy/set_echo.h"
#include "proxy/handler.h"
#include "proxy/globals.h"

#include "clipp.h"

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

}

namespace cw {
namespace proxy {

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
    run(ioc, ctx, tcp::endpoint{address, static_cast<unsigned short>(port)}, force_ssl, !no_websocket);

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

}
}


int main(int argc, char **argv) {
    using namespace cw::proxy;

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
