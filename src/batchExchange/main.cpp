/**
 * @file main.cpp
 * @brief CLI
 *
 ***********************************************/

#include <curl/curl.h>
#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "CBatchSlurm.h"
#include "CXCat.h"
#include "clipp.h"
#include "restClient.h"
#include "sessionTokenTypes.h"
#include "utils.h"

#define DRAIN_SLEEP 5000

bool canceled(false);

/**
 * @brief Handle caught signal
 *
 * This function is called when SIGINT is caught.
 *
 * @param signal Number of signal
 */
void sigHandler(int signal) {
    std::cout << "Caught signal " << signal << std::endl;

    // only exit on second SIGINT
    if (canceled) {
        exit(EXIT_FAILURE);
    }
    canceled = true;
}

int main(int argc, char **argv) {
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = sigHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL); /* for CTRL+C */

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
    std::string batchSystem = "slurm",
                loginPath = "",
                nodes = "",
                state = "",
                jobs = "",
                queues = "",
                reason = "",
                images = "",
                image = "",
                prescripts = "",
                postbootscripts = "",
                groups = "";

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
    auto deployOpt = (clipp::command("deploy").set(selected, mode::deploy), clipp::value("nodes/groups", nodes), (clipp::option("--image") & clipp::value("image", image)), (clipp::option("--prescripts") & clipp::value("prescripts", prescripts)), (clipp::option("--postbootscripts") & clipp::value("postbootscripts", postbootscripts))) % "Deploy <image> on <nodes/groups>";
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
                if (slurmSession.get_node_states(nodeList, output) != 0)
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
            std::vector<std::string> availableGroups, targetNodes, targetGroups, combinedTargetNodes;
            if (xcatSession.get_group_names(availableGroups) != 0)
                return 1;

            // check if specified targets are a groups or nodes
            for (auto &entry : nodeList) {
                if (!utils::vector_contains(availableGroups, entry))
                    targetNodes.push_back(entry);
                else {
                    targetGroups.push_back(entry);
                }
            }

            // nodeList now holds a list of all nodes even if they were specified as a group
            nodeList = targetNodes;
            for (auto &group : targetGroups) {
                std::vector<std::string> members;
                if (xcatSession.get_group_members(group, members) != 0)
                    return 1;
                for (auto &member : members)
                    nodeList.push_back(member);
            }

            // TODO filter duplicates, evaluate if any further action is required. Groups should be prioritized over nodes
            // Example input: "nodes,node1" where nodes is a group containing the member "nodes1" while node1 is also given seperately

            std::cout << "TARGETNODES: \n";
            for (auto &group : targetNodes) {
                std::cout << group << std::endl;
            }
            std::cout << std::endl;

            std::cout << "NODELIST: \n";
            for (auto &group : nodeList) {
                std::cout << group << std::endl;
            }
            std::cout << std::endl;

            std::cout << "TARGETGROUPS: \n";
            for (auto &group : targetGroups) {
                std::cout << group << std::endl;
            }
            std::cout << std::endl;

            // check validity of chosen image or generate image options
            std::vector<std::string> availableImages;

            if (xcatSession.get_os_image_names(availableImages) != 0)
                return 1;

            if (!availableImages.size()) {
                std::cerr << "No deployable images found!" << std::endl;
                return 1;
            }

            if (image.length() && !utils::vector_contains(availableImages, image)) {
                std::cerr << "Unknown Image" << std::endl;
                image = "";
            }

            // TODO handle cin cancel

            if (!image.length()) {
                std::cout << "Please select one of the following images (by number):\n\n";
                for (size_t i = 1; i <= availableImages.size(); i++) {
                    std::cout << "(" << i << ")\t" << availableImages[i - 1] << std::endl;
                }
                std::cout << "\n";
                std::cin >> image;
                bool valid = utils::is_number(image);
                int imageNr;
                if (valid) {
                    imageNr = std::stoi(image);
                    if (imageNr < 1 || imageNr > static_cast<int>(availableImages.size()))
                        valid = false;
                }

                if (!valid) {
                    std::cerr << "Invalid selection" << std::endl;
                    return 1;
                }

                image = availableImages[imageNr - 1];
            }

            // TODO handle cancellation or errors during deployment! (rollback?)

            std::cout << "\nDraining nodes" << std::endl;
            if (slurmSession.drain_nodes(nodeList, "redeployment") != 0)
                return 1;

            unsigned int drained = 0;
            unsigned int nodeCount = nodeList.size();

            while (drained != nodeCount && !canceled) {
                if (slurmSession.drained(nodeList, drained) != 0)
                    return 1;
                std::cout << "\x1b[A"
                          << "Draining nodes [" << drained << "/" << nodeCount << "]" << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(DRAIN_SLEEP));
            }

            if (canceled)
                return 1;

            std::cout << "\x1b[A"
                      << "Draining complete.\n"
                      << std::endl;

            // TODO add postscripts

            std::string payload = "{";
            if (prescripts.length())
                payload += "\"prescripts\"=\"" + prescripts + "\",";
            if (postbootscripts.length())
                payload += "\"postbootscripts\"=\"" + postbootscripts + "\",";
            payload += "}";

            for (auto &group : targetGroups) {
                xcatSession.set_group_attributes(group, payload);
            }

            xcatSession.set_node_attributes(targetNodes, "");

            // TODO check if os image can be set via group

            // if (xcatSession.set_os_image(nodeList, image) != 0)
            //     return 1;
            std::cout << "Set OS image to '" << image << "' for next boot" << std::endl;

            // if (xcatSession.reboot_nodes(nodeList) != 0)
            //     return 1;

            // TODO wait until reboot is complete
            // either xcat provides an api for that
            // or check boot status

            break;
        }
        default:
            break;
    }

    std::cout << output << std::endl;

    slurmSession.logout();

    return 0;
}
