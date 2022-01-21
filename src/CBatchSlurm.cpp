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
CBatchSlurm::CBatchSlurm(std::string host, std::string port, std::string username, std::string password, bool sslVerify) {
    slurmSession = new RestClient(SESSION_TOKEN_BASIC_AUTH);
    slurmSession->set_user_credentials(username, password);
    slurmSession->set_host_config(host, port);
    slurmSession->ssl_verify(sslVerify);
}

/**
 * @brief Destructor
 */
CBatchSlurm::~CBatchSlurm() {
    delete this->slurmSession;
}

int CBatchSlurm::login() {
    return slurmSession->login();
}

void CBatchSlurm::getApiVersion() {
    /* api version already set */
    if (apiVersion.length()) return;

    std::string header, response;

    slurmSession->get("/openapi.json", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;
}

std::string CBatchSlurm::getJobs(int jobId = -1) {
    std::string header, response;
    slurmSession->get("slurm/v0.0.36/nodes", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;

    return response;
    if (jobId != -1) {
        // /slurm/{vApi}/jobs
    } else {
        // /slurm/{vApi}/job/{jobId}
    }
}

std::string CBatchSlurm::getNodes(std::string node) {
    if (node == "") {
        // /slurm/{vApi}/nodes
    } else {
        // /slurm/{vApi}/node/{node}
    }
}

std::string CBatchSlurm::getQueues(std::string queue) {
    if (queue == "") {
        // /slurm/{vApi}/partition
    } else {
        // /slurm/{vApi}/partitions/{queue}
    }
}
std::string CBatchSlurm::getNodeStatus(std::string) {
    //
}

int CBatchSlurm::setNodeStatus(std::vector<std::string> nodeList, std::string status) {
    // custom webserver
    // [POST] /v1/slurm/status?nodes=a,b
}