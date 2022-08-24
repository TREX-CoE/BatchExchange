/**
 * @file main.cpp
 * @brief Proxy
 *
 * ./src/proxy/proxy --cred ../data/creds run --cert ../data/server.crt --priv ../data/server.key --dh ../data/dh2048.pem --port 2000 --host 0.0.0.0
 *
 * wscat -n -c "wss://127.0.0.1:2000/"
 * {"command": "login", "user": "admin", "password": "admin"}
 * {"command": "xcat/set", "user": "admin", "password": "admin", "host": "127.0.0.1", "port": 3000}
 * {"command": "xcat/login", "user": "admin", "password": "admin", "host": "127.0.0.1", "port": 3000}
 * {"command": "detect", "batchsystem": "slurm"}
 **/

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <functional>
#include <iostream>

#include <cassert>
#include <stdlib.h>


#include "proxy/cmd_user.h"
#include "proxy/cmd_run.h"

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
        case mode::user_set: return cmd::user::set(cred, username, scopes, defaults::password_prompt);
        case mode::user_remove: return cmd::user::remove(cred, username);
        case mode::run: return cmd::run(cred, threads, host, port, cert, priv, dh, force_ssl, no_ssl, no_websocket);
    }


    return 0;
}
