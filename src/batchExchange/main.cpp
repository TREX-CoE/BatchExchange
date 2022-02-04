/**
 * @file main.cpp
 * @brief CLI
 *
 ***********************************************/

#include <curl/curl.h>

#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "CBatchSlurm.h"
#include "CXCat.h"
#include "clipp.h"
#include "restClient.h"
#include "sessionTokenTypes.h"
#include "utils.h"

int main(int argc, char **argv) {
    enum class mode { nodes,
                      jobs,
                      state,
                      queues,
                      images,
                      bootstate,
                      reboot,
                      deploy
    };

    mode selected;
    bool help = false, json = true;
    std::string batchSystem = "slurm", loginPath = "", nodes = "", state = "", jobs = "", queues = "", reason = "", images = "", image = "";

    auto generalOpts = (clipp::option("-h", "--help").set(help) % "Shows this help message",
                        clipp::option("--json").set(json) % "Output as json",
                        (clipp::option("-b", "--batch") & (clipp::required("slurm") | clipp::required("pbs"))) % "Batch System",
                        (clipp::option("-l", "--loginFile") & clipp::value("path", loginPath)) % "Path for login data");

    auto nodesOpt = (clipp::command("nodes").set(selected, mode::nodes), clipp::opt_value("nodes", nodes)) % "Get node information [of <nodes>]";
    auto jobsOpt = (clipp::command("jobs").set(selected, mode::jobs), clipp::opt_value("jobIDs", jobs)) % "Get job info [of <jobIDs>]";
    auto stateOpt = (clipp::command("state").set(selected, mode::state), (clipp::opt_value("nodes", nodes), (clipp::option("--state") & clipp::value("state", state), (clipp::option("--reason") & clipp::value("reason", reason))))) % "Get/Set state [of <nodes>]";
    auto queueOpt = (clipp::command("queues").set(selected, mode::queues), clipp::opt_value("queues", queues)) % "Get queue information [of <queues>]";
    auto imageOpt = (clipp::command("images").set(selected, mode::images), clipp::opt_value("images", images)) % "Get information for available images [<images>]";
    auto bootStateOpt = (clipp::command("bootstate").set(selected, mode::bootstate), clipp::opt_value("nodes", nodes)) % "Get bootstate [of <nodes>]";
    auto rebootOpt = (clipp::command("reboot").set(selected, mode::reboot), clipp::value("nodes", nodes)) % "Reboot <nodes>";
    auto deployOpt = (clipp::command("deploy").set(selected, mode::deploy), clipp::value("nodes", nodes) & (clipp::option("--image") & clipp::value("image", image))) % "Deploy <image> on <nodes>";
    auto cli = ("COMMANDS\n" % (deployOpt | nodesOpt | stateOpt | jobsOpt | queueOpt | imageOpt | bootStateOpt | rebootOpt), "OPTIONS\n" % generalOpts);

    if (!clipp::parse(argc, argv, cli) || help) {
        // std::cout << make_man_page(cli, argv[0]) << std::endl;
        std::cout << "USAGE:\n"
                  << clipp::usage_lines(cli, argv[0]) << "\n\n\n"
                  << "PARAMETERS:\n\n"
                  << clipp::documentation(cli) << std::endl;
        return 1;
    }

    // TODO implement EITHER loginFile OR manualy specification of all login parameters (can be solved using groups)
    if (!loginPath.length()) {
        std::cout << "Please specify login file" << std::endl;
        return 1;
    }

    std::cout << "Reading login data from " << loginPath << std::endl;
    utils::loginData megwareLogin, xCatLogin, slurmLogin;
    utils::read_login_data(loginPath, megwareLogin, xCatLogin, slurmLogin);

    CBatchSlurm slurmSession(slurmLogin.host, slurmLogin.port, slurmLogin.username, slurmLogin.password, false);
    CXCat xcatSession(xCatLogin.host, xCatLogin.port, xCatLogin.username, xCatLogin.password, false);

    // TODO log in only when really needed
    if (slurmSession.login() != 0) {
        std::cerr << "Slurm Login failed on " << slurmLogin.host << ":" << slurmLogin.port << " failed" << std::endl;
        return 1;
    }

    if (xcatSession.login() != 0) {
        std::cerr << "xCAT Login failed on " << xCatLogin.host << ":" << xCatLogin.port << " failed" << std::endl;
        return 1;
    }

    std::vector<std::string> nodeList, jobList, queueList, imageList;

    utils::decode_brace(nodes, nodeList);
    utils::decode_brace(queues, queueList);
    utils::decode_brace(jobs, jobList);
    utils::decode_brace(images, imageList);

    std::string output;
    switch (selected) {
        case mode::nodes: {
            if (slurmSession.get_nodes(nodeList, output) != 0)
                return 1;
            break;
        }
        case mode::jobs: {
            if (slurmSession.get_jobs(jobList, output) != 0)
                return 1;
            break;
        }
        case mode::queues: {
            if (slurmSession.get_queues(queueList, output) != 0)
                return 1;
            break;
        }
        case mode::state: {
            // TODO check for reason for certain states
            if (nodes.length() && state.length()) {
                if (slurmSession.set_node_state(nodeList, state, reason) != 0)
                    return 1;
                else {
                    std::cout << "State for '" << nodes << "' set to '" << state << "'";
                    if (reason.length())
                        std::cout << "(" << reason << ")";
                    std::cout << std::endl;
                    return 0;
                }
            } else {
                if (slurmSession.get_node_state(nodeList, output) != 0)
                    return 1;
            }
            break;
        }
        case mode::images: {
            if (xcatSession.get_os_images(imageList, output) != 0)
                return 1;

            break;
        }
        case mode::bootstate: {
            if (xcatSession.get_bootstate(nodeList, output) != 0)
                return 1;
            break;
        }
        case mode::reboot: {
            if (xcatSession.reboot_nodes(nodeList) != 0)
                return 1;
            break;
        }
        case mode::deploy: {
            break;
        }
        default:
            break;
    }

    std::cout << output << std::endl;

    slurmSession.logout();

    return 0;
}
