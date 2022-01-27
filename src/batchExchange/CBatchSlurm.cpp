/**
 * @file CBatchSlurm.h
 * @brief CBatch Slurm implementation
 *
 ***********************************************/

#include "CBatchSlurm.h"

#include <algorithm>
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
    std::string _, response;

    int res = openapiSession->get("/openapi.json", response, _);
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

/**
 * @brief Wrapper for get-requests
 *
 * @param path API path
 * @param output Reference for output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get(std::string path, std::string& output) {
    std::string _;
    int res = session->get(path, output, _);
    if (res != 0 && res != 200) {
        std::cerr << "Error calling GET " << path << "(" << res << ")" << std::endl;
        return 1;
    }
    return 0;
}

/**
 * @brief Get job information
 *
 * Slurm currently does not provide a way to query multiple specified jobs with a single call.
 * Therefore all jobs are queried and then filtered.
 * @param jobIds Job Id(s)
 * @param output Reference for output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_jobs(std::string jobIds, std::string& output) {
    // TODO implement filter
    return get("/slurm/" + apiVersion + "/jobs", output);
}

/**
 * @brief Get node information
 *
 * Slurm currently does not provide a way to query multiple specified nodes with a single call.
 * Therefore all nodes are queried and then filtered.
 * @param jobIds Nodes(s)
 * @param output Reference for output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_nodes(std::string nodes, std::string& output) {
    // TODO implement filter
    return get("/slurm/" + apiVersion + "/nodes", output);
}

/**
 * @brief Get queue information
 *
 * Slurm currently does not provide a way to query multiple specified queues with a single call.
 * Therefore all queues are queried and then filtered.
 * @param queues Queue(s)
 * @param output Reference for output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_queues(std::string queues, std::string& output) {
    // TODO implement filter
    return get("/slurm/" + apiVersion + "/partitions", output);
}

int CBatchSlurm::get_node_state(std::string nodes, std::string& output) {
    std::string nodeData;
    if (get_nodes(nodes, nodeData) != 0)
        return 1;

    rapidjson::Document doc;
    rapidjson::Document stateDoc;
    auto& allocator = stateDoc.GetAllocator();
    stateDoc.SetObject();
    doc.Parse(nodeData.c_str());

    if (doc.HasMember("nodes")) {
        for (auto& v : doc["nodes"].GetArray()) {
            if (!v.HasMember("state") || !v.HasMember("hostname"))
                continue;
            stateDoc.AddMember(rapidjson::Value(v["hostname"].GetString(), allocator).Move(),
                               rapidjson::Value(v["state"].GetString(), allocator).Move(),
                               allocator);
        }
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    stateDoc.Accept(writer);

    output = buffer.GetString();
    return 0;
}

int CBatchSlurm::set_node_state(const std::vector<std::string>& nodeList, std::string state) {
    if (!nodeList.size()) {
        std::cerr << "Error - Missing nodes" << std::endl;
        return 1;
    }

    utils::to_lower(state);
    if (!(std::find(utils::slurmNodeStates.begin(), utils::slurmNodeStates.end(), state) != utils::slurmNodeStates.end())) {
        std::cerr << "Error - " << state << " is not a valid node state" << std::endl;
        return 1;
    }

    rapidjson::Document doc;
    auto& allocator = doc.GetAllocator();
    doc.SetObject();

    doc.AddMember(
        rapidjson::StringRef("state"),
        rapidjson::StringRef(state.c_str()),
        allocator);

    rapidjson::Value nodes(rapidjson::kArrayType);

    for (const auto& v : nodeList)
        nodes.PushBack(rapidjson::Value{}.SetString(v.c_str(), v.length(), allocator), allocator);

    doc.AddMember("nodes", nodes, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    std::string postData = buffer.GetString();
    std::cout << "POSTDATA\n"
              << postData << std::endl;
    std::string header, response;
    const std::string path = "/slurm/nodes/state";
    int res = session->post("/slurm/nodes/state", postData, response, header);
    if (res != 0 && res != 200) {
        std::cerr << "Error calling POST" << path << "(" << res << ")" << std::endl;
        return 1;
    }

    // custom webserver
    // [POST] /v1/slurm/state?nodes=a,b
    return 0;
}