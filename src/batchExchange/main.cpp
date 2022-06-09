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
#include "../restclient/src/restClient.h"
#include "../restclient/src/sessionTokenTypes.h"
#include "utils.h"

#define DRAIN_SLEEP 3000

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
    bool help = false, json = true, deployTargetIsGroup = false;
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
                postscripts = "",
                provmethod = "";

    auto generalOpts = (clipp::option("-h", "--help").set(help) % "Shows this help message",
                        clipp::option("--json").set(json) % "Output as json",
                        (clipp::option("-b", "--batch").set(batchSystem) & (clipp::required("slurm") | clipp::required("pbs"))) % "Batch System",
                        (clipp::option("-l", "--loginFile") & clipp::value("path", loginPath)) % "Path for login data");

    auto nodesOpt = (clipp::command("nodes").set(selected, mode::nodes), clipp::opt_value("nodes", nodes)) % "Get node information [of <nodes>]";
    auto jobsOpt = (clipp::command("jobs").set(selected, mode::jobs), clipp::opt_value("jobIDs", jobs)) % "Get job info [of <jobIDs>]";
    auto stateOpt = (clipp::command("state").set(selected, mode::state), (clipp::opt_value("nodes", nodes), (clipp::option("--state") & clipp::value("state", state), (clipp::option("--reason") & clipp::value("reason", reason))))) % "Get/Set state [of <nodes>]";
    auto queueOpt = (clipp::command("queues").set(selected, mode::queues), clipp::opt_value("queues", queues)) % "Get queue information [of <queues>]";
    auto imageOpt = (clipp::command("images").set(selected, mode::images), clipp::opt_value("images", images)) % "Get information for available images [<images>]";
    auto bootStateOpt = (clipp::command("bootstate").set(selected, mode::bootstate), clipp::opt_value("nodes", nodes)) % "Get bootstate [of <nodes>]";
    auto rebootOpt = (clipp::command("reboot").set(selected, mode::reboot), clipp::value("nodes", nodes)) % "Reboot <nodes>";
    auto deployOpt = (clipp::command("deploy").set(selected, mode::deploy), clipp::value("nodes", nodes), clipp::option("--group").set(deployTargetIsGroup), (clipp::option("--image") & clipp::value("image", image)), (clipp::option("--prescripts") & clipp::value("prescripts", prescripts)), (clipp::option("--postbootscripts") & clipp::value("postbootscripts", postbootscripts)), (clipp::option("--postscripts") & clipp::value("postscripts", postscripts), (clipp::option("--provmethod") & clipp::value("provmethod", provmethod)))) % "Deploy <image> on <nodes/groups>";
    auto cli = ("COMMANDS\n" % (deployOpt | nodesOpt | stateOpt | jobsOpt | queueOpt | imageOpt | bootStateOpt | rebootOpt), "OPTIONS\n" % generalOpts);

    if (!clipp::parse(argc, argv, cli) || help) {
        // std::cout << make_man_page(cli, argv[0]) << std::endl;
        std::cout << "USAGE:\n"
                  << clipp::usage_lines(cli, argv[0]) << "\n\n\n"
                  << "PARAMETERS:\n\n"
                  << clipp::documentation(cli) << std::endl;
        return 1;
    }

    // TODO implement EITHER loginFile OR manualy specification of all login parameters (can be solved using clipp groups)
    if (!loginPath.length()) {
        std::cout << "Please specify login file" << std::endl;
        return 1;
    }

    std::cout << "Reading login data from " << loginPath << std::endl;
    utils::loginData megwareLogin, xCatLogin, slurmLogin;
    if (utils::read_login_data(loginPath, megwareLogin, xCatLogin, slurmLogin) != 0)
        exit(EXIT_FAILURE);

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
            std::vector<std::string> targetNodes, targetGroups;
            if (!deployTargetIsGroup)
                targetNodes = nodeList;
            else {
                targetGroups = nodeList;
                nodeList.clear();

                // nodeList shall hold a list of all nodes even if they were specified as a group
                for (auto &group : targetGroups) {
                    std::vector<std::string> members;
                    if (xcatSession.get_group_members(group, members) != 0)
                        return 1;
                    for (auto &member : members)
                        nodeList.push_back(member);
                }
            }

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

            std::cout << "\nDraining nodes"
                      << std::endl;
            if (slurmSession.drain_nodes(nodeList, "redeployment") != 0)
                return 1;

            unsigned int drained = 0;
            unsigned int nodeCount = nodeList.size();

            if (slurmSession.drained(nodeList, drained) != 0)
                return 1;

            while (drained != nodeCount && !canceled) {
                if (slurmSession.drained(nodeList, drained) != 0)
                    return 1;
                std::cout << "\x1b[A"
                          << "Draining nodes [" << drained << "/" << nodeCount << "]"
                          << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(DRAIN_SLEEP));
            }

            if (canceled)
                return 1;

            std::cout << "\x1b[A"
                      << "Draining complete."
                      << std::endl;

            rapidjson::Document attributes;
            attributes.SetObject();
            auto &allocator = attributes.GetAllocator();

            if (provmethod.length())
                attributes.AddMember(rapidjson::StringRef("provmethod"),
                                     rapidjson::StringRef(provmethod.c_str()),
                                     allocator);

            if (prescripts.length())
                attributes.AddMember(rapidjson::StringRef("prescripts"),
                                     rapidjson::StringRef(prescripts.c_str()),
                                     allocator);
            if (postbootscripts.length())
                attributes.AddMember(rapidjson::StringRef("postbootscripts"),
                                     rapidjson::StringRef(postbootscripts.c_str()),
                                     allocator);
            if (postscripts.length())
                attributes.AddMember(rapidjson::StringRef("postscripts"),
                                     rapidjson::StringRef(postscripts.c_str()),
                                     allocator);

            std::string attributesStr;
            utils::rapidjson_doc_to_str(attributes, attributesStr);
            std::cout << attributesStr << std::endl;

            for (auto &group : targetGroups) {
                xcatSession.set_group_attributes(group, attributesStr);
                std::cout << "Set attributes for group '" << group << "'" << std::endl;
            }

            if (targetNodes.size()) {
                xcatSession.set_node_attributes(targetNodes, attributesStr);
                std::cout << "Set attributes for nodes: " << utils::join_vector_to_string(targetNodes, ",") << std::endl;
            }

            xcatSession.set_os_image(deployTargetIsGroup ? targetGroups : targetNodes, image);
            std::cout << "Set OS image to '" << image << "' for next boot" << std::endl;

            if (xcatSession.reboot_nodes(nodeList) != 0)
                return 1;

            std::cout << "Node reset ordered\n";

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
