/**
 * @file CBatchSlurm.h
 * @brief CBatch Slurm implementation
 *
 * Slurm currently does not provide a way to query multiple specified resources with a single call.
 * Therefore the whole collection is queried and then filtered.
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
    delete openapiSession;
    delete session;
}

/**
 * @brief Login session
 *
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::login() {
    openapiSession->login();
    int res = session->login();
    get_api_version();
    return res;
}

/**
 * @brief Logout session
 *
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::logout() {
    openapiSession->logout();
    return session->logout();
}

/**
 * @brief Check slurm output for errors
 *
 * @param o output
 * @return 0 No errors
 * @return 1 Errors found
 */
int CBatchSlurm::check_errors(const std::string& o) {
    rapidjson::Document d;
    if (d.Parse(o.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    if (d.HasMember("errors")) {
        if (d["errors"].IsString()) {
            std::string err = d["errors"].GetString();
            if (err.length()) {
                std::cerr << err << std::endl;
                return 1;
            }
        } else if (d["errors"].IsArray()) {
            auto err = d["errors"].GetArray();
            for (rapidjson::SizeType i = 0; i < err.Size(); i++)
                if (err[i].IsString())
                    std::cerr << err[i].GetString() << std::endl;
        }
    }
    return 0;
}

/**
 * @brief Filter entries from JSON
 *
 * @param filter
 * @param input input data
 * @param output output
 * @param objectName object name to be checked
 * @param identifier identifier to be checked against the filter
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::filter_output(const std::vector<std::string>& filter, const std::string& input, std::string& output, std::string objectName, std::string identifier) {
    rapidjson::Document d;

    if (d.Parse(input.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }
    rapidjson::Document fd;
    fd.SetArray();
    rapidjson::Document::AllocatorType& allocator = fd.GetAllocator();
    if (d.HasMember(objectName.c_str())) {
        rapidjson::Value& nodeEntries = d[objectName.c_str()];
        for (rapidjson::SizeType i = 0; i < nodeEntries.Size(); i++) {
            if (nodeEntries[i].HasMember(identifier.c_str())) {
                std::string name = nodeEntries[i][identifier.c_str()].GetString();
                if (!filter.size() || utils::vector_contains(filter, name))
                    fd.PushBack(nodeEntries[i].GetObject(), allocator);
            }
        }
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        fd.Accept(writer);

        output = buffer.GetString();
    }
    return 0;
}

/**
 * @brief Retrieve slurm api version from openapi specification
 *
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_api_version() {
    std::string _, response;

    int res = openapiSession->get("/openapi.json", response, _);
    if (res != 0 && res != 200) {
        std::cerr << "Error fetching slurm api version: " << res << std::endl;
        return 1;
    }

    rapidjson::Document doc;
    if (doc.Parse(response.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    if (!doc.HasMember("info") || !doc["info"].HasMember("version")) {
        std::cerr << "Unable to determine api version from /openapi.json" << std::endl;
        return 1;
    }

    apiVersion = "v" + static_cast<std::string>(doc["info"]["version"].GetString());
    std::cout << "API-Version: " << apiVersion << std::endl;
    return 0;
}

/**
 * @brief Wrapper for get-requests
 *
 * @param path API path
 * @param output  output
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
 * @param jobs Job Id(s)
 * @param output  output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_jobs(const std::vector<std::string>& filter, std::string& output) {
    std::string response;
    if (get("/slurm/" + apiVersion + "/jobs", response) != 0)
        return 1;
    if (check_errors(response) != 0)
        return 1;
    return filter_output(filter, response, output, "jobs", "job_id");
}

/**
 * @brief Get node information
 *
 * @param filter Nodes(s)
 * @param output  output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_nodes(const std::vector<std::string>& filter, std::string& output) {
    std::string response;
    if (get("/slurm/" + apiVersion + "/nodes", response) != 0)
        return 1;

    if (check_errors(response) != 0)
        return 1;

    return filter_output(filter, response, output, "nodes", "name");
}

/**
 * @brief Get queue information
 *
 * @param filter Queue(s)
 * @param output  output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_queues(const std::vector<std::string>& filter, std::string& output) {
    std::string response;
    if (get("/slurm/" + apiVersion + "/partitions", response) != 0)
        return 1;

    if (check_errors(response) != 0)
        return 1;

    return filter_output(filter, response, output, "partitions", "name");
}

/**
 * @brief Get node states
 *
 * @param filter Nodes(s)
 * @param output  output
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::get_node_state(const std::vector<std::string>& filter, std::string& output) {
    std::string nodeData;
    if (get_nodes(filter, nodeData) != 0)
        return 1;

    // Checking for errors and filtering are already performed by get_nodes
    rapidjson::Document doc;
    rapidjson::Document stateDoc;
    auto& allocator = stateDoc.GetAllocator();
    stateDoc.SetObject();
    doc.Parse(nodeData.c_str());

    for (auto& v : doc.GetArray()) {
        if (!v.HasMember("state") || !v.HasMember("hostname"))
            continue;
        stateDoc.AddMember(rapidjson::Value(v["hostname"].GetString(), allocator).Move(),
                           rapidjson::Value(v["state"].GetString(), allocator).Move(),
                           allocator);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    stateDoc.Accept(writer);

    output = buffer.GetString();
    return 0;
}

/**
 * @brief Set node information
 *
 * @param queues nodes list of nodes
 * @param state State to be set
 * @param reason Reason for state change
 * @return 0 Success
 * @return 1 Error
 */
int CBatchSlurm::set_node_state(const std::vector<std::string>& nodes, std::string state, std::string reason) {
    if (!nodes.size()) {
        std::cerr << "Error - Missing nodes" << std::endl;
        return 1;
    }

    utils::to_lower(state);
    if (!(std::find(utils::slurmNodeStates.begin(), utils::slurmNodeStates.end(), state) != utils::slurmNodeStates.end())) {
        std::cerr << "Error - '" << state << "' is not a valid state option [" << utils::join_vector_to_string(utils::slurmNodeStates, "|") << "]" << std::endl;
        return 1;
    }

    rapidjson::Document doc;
    auto& allocator = doc.GetAllocator();
    doc.SetObject();

    doc.AddMember(
        rapidjson::StringRef("state"),
        rapidjson::StringRef(state.c_str()),
        allocator);

    doc.AddMember(
        rapidjson::StringRef("reason"),
        rapidjson::StringRef(reason.c_str()),
        allocator);

    rapidjson::Value nodeList(rapidjson::kArrayType);

    for (const auto& v : nodes)
        nodeList.PushBack(rapidjson::Value{}.SetString(v.c_str(), v.length(), allocator), allocator);

    doc.AddMember("nodes", nodeList, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    std::string postData = buffer.GetString();
    std::string _, response;
    const std::string path = "/v1/slurm/nodes/state";
    int res = session->post(path, postData, response, _);
    if (res != 0 && res != 200) {
        std::cerr << "Error calling POST " << path << "(" << res << ")" << std::endl;
        return 1;
    }

    return check_errors(response);
}