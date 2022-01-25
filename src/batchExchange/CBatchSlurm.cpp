/**
 * @file CBatchSlurm.h
 * @brief CBatch Slurm implementation
 *
 ***********************************************/

#include "CBatchSlurm.h"

/**
 * @brief Constructor
 */
CBatchSlurm::CBatchSlurm(std::string host, std::string port, std::string username, std::string password, bool sslVerify) {
    /*
     * The /openapi API calls require a different RestClient session as somehow
     * every API call that comes after them fails with curl error code 1.
     *
     * TODO find solution to resolve this issues within curl
     */
    openapiSession = new RestClient(SESSION_TOKEN_BASIC_AUTH);
    openapiSession->set_user_credentials(username, password);
    openapiSession->set_host_config(host, port);
    openapiSession->ssl_verify(sslVerify);

    session = new RestClient(SESSION_TOKEN_BASIC_AUTH);
    session->set_user_credentials(username, password);
    session->set_host_config(host, port);
    session->ssl_verify(sslVerify);
}

/**
 * @brief Destructor
 */
CBatchSlurm::~CBatchSlurm() {
    delete this->openapiSession;
    delete this->session;
}

int CBatchSlurm::login() {
    int res = session->login();
    get_api_version();
    return res;
}

int CBatchSlurm::logout() {
    return session->logout();
}

int CBatchSlurm::get_api_version() {
    std::string header, response;

    int res = openapiSession->get("/openapi.json", response, header);
    if (res != 0 && res != 200) {
        std::cerr << "Error fetching slurm api version: " << res << std::endl;
        return 1;
    }

    rapidjson::Document doc;
    doc.Parse(response.c_str());

    if (!doc.HasMember("info") || !doc["info"].HasMember("version")) {
        std::cerr << "Unable to determine api version from /openapi.json" << std::endl;
        return 1;
    }

    this->apiVersion = "v" + static_cast<std::string>(doc["info"]["version"].GetString());
    std::cout << "API-Version: " << apiVersion << std::endl;
    return 0;
}

int CBatchSlurm::get_jobs(int jobId = -1) {
    // std::string header, response;
    // session->get("/slurm/" + apiVersion + "/jobs", response, header);
    // std::cout << header << std::endl;
    // std::cout << response << std::endl;

    return 0;
}

/**
 * @brief Get basic node information
 *
 * Slurm currently does not provide a way to query multiple specified nodes with a single call.
 * Therefore all nodes are queried and then filtered.
 * @param nodes Node(s)
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_nodes(std::string nodes, std::string& output, bool json) {
    std::string header, response;
    std::cout << this->apiVersion << std::endl;
    int res = session->get("/slurm/v0.0.36/nodes", response, header);
    if (res != 0 && res != 200) {
        std::cerr << "Error fetching nodes: " << res << std::endl;
        return 1;
    }
    std::cout << header << std::endl;
    std::cout << response << std::endl;

    return 0;
}

int CBatchSlurm::get_queues(std::string queue) {
    return 0;
}
int CBatchSlurm::get_node_state(std::string) {
    return 0;
}

int CBatchSlurm::set_node_state(std::vector<std::string> nodeList, std::string status) {
    // custom webserver
    // [POST] /v1/slurm/status?nodes=a,b
    return 0;
}