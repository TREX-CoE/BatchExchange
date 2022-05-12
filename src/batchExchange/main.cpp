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

#include "batchsystem/batchsystem.h"
#include "batchsystem/factory.h"

#include <reproc++/run.hpp>

namespace batch = cw::batch;

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


int runCommand(std::string& out, const cw::batch::CmdOptions& opts) {
        std::vector<std::string> args{opts.cmd};
        for (const auto& a: opts.args) args.push_back(a);

        reproc::process process;
        std::error_code ec_start = process.start(args);
        if (ec_start) return -1;

        reproc::sink::string sink(out);
        std::error_code ec_drain = reproc::drain(process, sink, reproc::sink::null);
        if (ec_drain) return -1;

        auto ret = process.wait(reproc::infinite);
        if (ret.second) return -1;

        return ret.first;
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

    batch::System batchSystem; 

    std::string loginPath = "",
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
                        (clipp::option("-b", "--batch") & (clipp::required("slurm").set(batchSystem, batch::System::Slurm) | clipp::required("pbs").set(batchSystem, batch::System::Pbs) | clipp::required("lsf").set(batchSystem, batch::System::Lsf))) % "Batch System",
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

    batch::BatchSystem batch;
    create_batch(batch, batchSystem, runCommand);


    return 0;
}
