#include <curl/curl.h>

#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "CBatchSlurm.h"
#include "clipp.h"
#include "restClient.h"
#include "sessionTokenTypes.h"
#include "utils.h"
#include "xcat.h"

int main(int argc, char** argv) {
    // variables storing the parsing result; initialized with their default values
    enum class mode { info,
                      state,
    };
    mode selected = mode::info;

    std::string loginPath = "";
    bool help = false;
    bool json = true;
    std::string batchSystem;
    std::string nodes = "";
    std::string state = "";
    auto generalOpts = (clipp::option("-h", "--help").set(help) % "Shows this help message",
                        clipp::option("--json").set(json) % "Output as json",
                        (clipp::option("-b", "--batch") & (clipp::required("slurm") | clipp::required("pbs"))) % "Batch System",
                        (clipp::option("-l", "--loginFile") & clipp::value("path", loginPath)) % "Path for login data");

    auto infoOpt = (clipp::command("info").set(selected, mode::info), clipp::opt_value("nodes", nodes)) % "Get basic information for <nodes>";
    auto stateOpt = (clipp::command("state").set(selected, mode::info), clipp::opt_value("nodes", nodes), clipp::opt_value("state", state)) % "Get/Set status for <nodes>";

    auto cli = ((infoOpt | stateOpt), generalOpts);

    if (!clipp::parse(argc, argv, cli)) {
        std::cout << "Invalid" << std::endl;
        std::cout << make_man_page(cli, argv[0]) << '\n';
        return 1;
    }

    if (help) {
        std::cout << clipp::make_man_page(cli, argv[0]);
        return 0;
    }

    // TODO implement EITHER loginFile or manualy specification of all login parameters (can be solved using groups)
    // if (!loginPath.length) {
    //     std::cout << "Please specify login file" << std::endl;
    //     return 1;
    // }

    // std::cout << "Reading login data from " << loginPath << std::endl;
    // utils::read_login_data(loginPath, megwareLogin, xCatLogin, slurmLogin);

    // ////// slurm

    // CBatchSlurm slurmSession(slurmLogin.host, slurmLogin.port, slurmLogin.username, slurmLogin.password, false);

    // int errorCode = slurmSession.login();

    // std::cout << "login error code: " << errorCode << std::endl;
    // std::cout << slurmSession.get_nodes() << std::endl;

    // slurmSession.logout();

    ////// xCat

    /*Xcat xCat;
    xCat.set_user_credentials(xCatLogin.username, xCatLogin.password);
    xCat.set_host_config(xCatLogin.host, xCatLogin.port);
    xCat.ssl_verify(false);

    int errorCode = xCat.login();

    std::string currentImage = xCat.get_os_image("cn1");*/
    // if (currentImage.find("centos8-x86_64-netboot-compute") == std::string::npos) {
    // xCat.set_os_image("cn1", "compute-alma8-diskless");
    //} else {
    // xCat.set_os_image("cn1", "centos8-x86_64-netboot-compute");
    //}
    // xCat.reboot_node("cn1");

    // xCat.logout();

    // Check command line arguments.
    /*if (argc != 4)
    {
        std::cerr <<
            "Usage: websocket-server-async <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    websocket-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Create and launch a listening port
    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

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

    return EXIT_SUCCESS;*/

    /****************** REST Tests ********************/

    // MEGWARE
    /*
        RestClient rest(SESSION_TOKEN_MEGWARE);
        rest.set_user_credentials(megware.username, megware.password);
        rest.set_host_config(megware.host, megware.port);
        rest.ssl_verify(false);

        int errorCode = rest.login();
        std::cout << "login" << std::endl;
        std::cout << "errorCode: " << errorCode << std::endl;

        std::string header, response;
        //rest.post("api/v1/racks", "[{\"position\": 10, \"rack_name\": \"curlRack\", \"height\": 10, \"position\": 99}]", response, header);
        errorCode = rest.get("api/v1/racks/", response, header);
        //rest.patch("api/v1/racks/curlRack", "{\"height\": 42}", response, header);
        //rest.get("api/v1/racks/curlRack", response, header);
        //rest.del("api/v1/racks/curlRack", response, header);
        std::cout << "errorCode: " << errorCode << std::endl;
        std::cout << "get" << std::endl;

        rest.logout();
        std::cout << "logout" << std::endl;

        std::cout << header << std::endl;
        std::cout << "------------" << std::endl;
        std::cout << response << std::endl;
    */

    // XCAT TOKEN
    /*
        RestClient rest(SESSION_TOKEN_XCAT);
        rest.set_user_credentials(xCatLogin.username, xCatLogin.password);
        rest.set_host_config(xCatLogin.host, xCatLogin.port);
        rest.ssl_verify(false);

        int errorCode = rest.login();
        std::cout << "login" << std::endl;
        std::cout << "errorCode: " << errorCode << std::endl;

        std::string header, response;
        //errorCode = rest.get("xcatws/nodes", response, header);
        errorCode = rest.get("xcatws/nodes/cn1/bootstate", response, header);
        errorCode = rest.put("xcatws/nodes/cn1/bootstate", "{\"osimage\":\"centos8-x86_64-netboot-compute\"}", response, header);

        std::cout << "errorCode: " << errorCode << std::endl;
        std::cout << "get" << std::endl;

        rest.logout();
        std::cout << "logout" << std::endl;

        std::cout << header << std::endl;
        std::cout << "------------" << std::endl;
        std::cout << response << std::endl;
    */
    /****************** Session Tests ********************/

    // MEGWARE TOKEN
    /*
        HttpSession session(
            megware.username,
            megware.password,
            megware.host,
            megware.port
        );

        session.set_token_type(SESSION_TOKEN_MEGWARE);
        session.set_login_path("/oauth/token");
        session.set_logout_path("/oauth/revoke");
        session.ssl_verify(false);

        int errorCode = session.login();
        if (errorCode != 0) {
            std::cout << "login failed with error code: " << errorCode << std::endl;
            return -1;
        }
        errorCode = session.logout();
        if (errorCode != 0) {
            std::cout << "logout failed with error code: " << errorCode << std::endl;
            return -2;
        }
    */
    // XCAT TOKEN
    /*
        HttpSession session(
            xCatLogin.username,
            xCatLogin.password,
            xCatLogin.host,
            xCatLogin.port
        );

        session.set_token_type(SESSION_TOKEN_XCAT);
        session.set_login_path("/xcatws/tokens");
        session.set_date_parse_descr("%Y-%m-%d %H:%M:%S");
        session.ssl_verify(false);

        int errorCode = session.login();
        if (errorCode != 0) {
            std::cout << "login failed with error code: " << errorCode << std::endl;
            return -1;
        }
    */
    // not possible to logout
    /*errorCode = session.logout();
    if (errorCode != 0) {
        std::cout << "logout failed with error code: " << errorCode << std::endl;
        return -2;
    }*/

    /****************** Token Tests ********************/

    // MEGWARE TOKEN
    /*
        SessionToken token;
        token.set_keys_by_token_type(SESSION_TOKEN_KEYS_MEGWARE);
        token.read_token("{\"access_token\": \"pHfFnU2Muhg0kIPeoSYGrt71fQxC3h\", \"expires_in\": 3600, \"token_type\": \"Bearer\", \"scope\": \"alerts_delete alerts_read batch_read batch_write commands_read commands_write configclasses_control configclasses_delete configclasses_read configclasses_write logs_read graphs_delete graphs_read graphs_write emails_read emails_write emails_delete inventories_read inventories_write maintenence_admin metrics_delete metrics_read metrics_write oauth_admin pdus_control pdus_delete pdus_read pdus_write preferences_read preferences_write racks_control racks_delete racks_read racks_write thresholds_admin thresholds_read traps_write traps_read units_control units_delete units_read units_write users_delete users_read users_self_read users_self_write users_write values_read views_delete views_read views_write\", \"refresh_token\": \"9S4JfjWHt5BH7161HvSviBgEfRRMIl\", \"version\": \"0.1.0\"}");

        std::cout << token.get_access_token() << std::endl;
        std::cout << token.get_refresh_token() << std::endl;
    */
    // XCAT TOKEN
    /*
        SessionToken token;
        token.set_keys_by_token_type(SESSION_TOKEN_KEYS_XCAT);
        token.set_date_parse_descr("%Y-%m-%d %H:%M:%S");
        int error = token.read_token("{\"token\":{\"expire\":\"2021-8-27 14:00:18\",\"id\":\"2bbee803-7d0d-497e-a472-e62254cd1e30\"}}");

        std::cout << "error: " << error << std::endl;

        std::cout << token.get_expire_date()-time(nullptr) << std::endl;

        std::cout << "get_access_token: " << token.get_access_token() << std::endl;
    */

    return 0;
}
