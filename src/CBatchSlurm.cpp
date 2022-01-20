/**
 * @file CBatchSlurm.hpp
 * @author Nico Tippmann
 * @brief CBatch Slurm implementation
 *
 ***********************************************/

#include "CBatchSlurm.hpp"

/**
 * @brief Constructor
 */
CBatchSlurm::CBatchSlurm() {
    // RC = new RestClient(SESSION_TOKEN_BASIC);
}

/**
 * @brief Destructor
 */
CBatchSlurm::CBatchSlurm(){

};

std::string CBatchSlurm::getJobs(int jobId = -1) {
    if (jobId != -1) {
        // /slurm/{vApi}/jobs
    } else {
        // /slurm/{vApi}/job/{jobId}
    }
}

std::string CBatchSlurm::getNodes(std::string node = "") {
    if (node == "") {
        // /slurm/{vApi}/nodes
    } else {
        // /slurm/{vApi}/node/{node}
    }
}

std::string CBatchSlurm::getQueues(std::string queue = "") {
    if (queue == "") {
        // /slurm/{vApi}/partition
    } else {
        // /slurm/{vApi}/partitions/{queue}
    }
}
std::string getNodeStatus(std::string) {
    //
}

int CBatchSlurm::setNodeStatus(std::vector<std::string> nodeList, std::string status) {
    // custom webserver
    // [POST] /v1/slurm/status?nodes=a,b
}