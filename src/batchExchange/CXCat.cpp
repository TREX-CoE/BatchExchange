/**
 * @file CXCat.cpp
 * @brief CXCat implementation
 *
 *
 ***********************************************/

#include "CXCat.h"

#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "utils.h"

/**
 * @brief Constructor
 */
CXCat::CXCat(std::string host, std::string port, std::string username, std::string password, bool sslVerify) {
    session = new RestClient(SESSION_TOKEN_XCAT);
    session->set_user_credentials(username, password);
    session->set_host_config(host, port);
    session->ssl_verify(sslVerify);
}

/**
 * @brief Destructor
 */
CXCat::~CXCat() {
    delete session;
}

/**
 * @brief Login session
 *
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::login() {
    return session->login();
}

/**
 * @brief Logout session
 *
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::logout() {
    return session->logout();
}

/**
 * @brief Get information of all available nodes
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_nodes(std::string &output) {
    int res = session->call("GET", "xcatws/nodes", output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get os images
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_os_images(const std::vector<std::string> &filter, std::string &output) {
    std::string response, imageRange = "ALLRESOURCES";

    if (filter.size())
        imageRange = utils::join_vector_to_string(filter, ",");

    int res = session->call("GET", "xcatws/osimages/" + imageRange, output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get names of os images
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_os_image_names(std::vector<std::string> &output) {
    std::string response;
    std::vector<std::string> images;
    if (get_os_images(images, response) != 0)
        return 1;

    rapidjson::Document d;

    d.Parse(response.c_str());

    for (auto &i : d.GetObject()) {
        output.push_back(i.name.GetString());
    }

    std::sort(output.begin(), output.end());

    return 0;
}

/**
 * @brief Get os images
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_bootstate(const std::vector<std::string> &filter, std::string &output) {
    // this uri does not provide a way to query all nodes at once -> fetch all nodes and join to {noderange}
    std::string nodeRange = "";
    if (filter.size())
        nodeRange = utils::join_vector_to_string(filter, ",");
    else {
        std::string nodeList;
        if (get_nodes(nodeList) != 0)
            return 1;

        rapidjson::Document d;
        d.Parse(nodeList.c_str());

        auto list = d.GetArray();
        for (rapidjson::SizeType i = 0; i < list.Size(); i++) {
            if (list[i].IsString()) {
                if (i != 0)
                    nodeRange += ",";
                nodeRange += list[i].GetString();
            }
        }
    }
    int res = session->call("GET", "xcatws/nodes/" + nodeRange + "/bootstate", output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Set os image
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_os_image(const std::vector<std::string> &filter, std::string osImage) {
    if (!filter.size() || !osImage.length())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/bootstate", response, "{\"osimage\":\"" + osImage + "\"}");

    if (utils::check_errors(response) || res != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

/**
 * @brief Reboot nodes
 *
 * @param filter filter
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::reboot_nodes(const std::vector<std::string> &filter) {
    if (!filter.size())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/power", response, "{\"action\":\"reset\"}");

    if (utils::check_errors(response) || res != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

/**
 * @brief Set attributes of group
 *
 * @param group name of group
 * @param attributes json attributes
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_group_attributes(std::string group, const std::string &attributes) {
    if (!group.length())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/groups/" + group, response, attributes);

    if (utils::check_errors(response) || res != 0)
        return 1;

    std::cout << response << std::endl;

    return 0;
}

/**
 * @brief Set attributes of nodes
 *
 * @param nodes list of nodes
 * @param attributes json attributes
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_node_attributes(const std::vector<std::string> &nodes, const std::string &attributes) {
    if (!nodes.size())
        return 1;
    std::string nodeRange;
    nodeRange = utils::join_vector_to_string(nodes, ",");

    std::string response;
    int res = session->call("PUT", "xcatws/groups/" + nodeRange, response, attributes);

    if (utils::check_errors(response) || res != 0)
        return 1;

    std::cout << response << std::endl;

    return 0;
}

/**
 * @brief Get names of all groups
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group_names(std::vector<std::string> &output) {
    std::string response;
    std::vector<std::string> images;
    int res = session->call("GET", "xcatws/groups/", response);

    if (utils::check_errors(response) || res != 0)
        return 1;

    rapidjson::Document d;
    if (d.Parse(response.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }
    auto groups = d.GetArray();
    for (rapidjson::SizeType i = 0; i < groups.Size(); i++) {
        if (groups[i].IsString())
            output.push_back(groups[i].GetString());
    }

    return 0;
}

/**
 * @brief Get attributes of group
 *
 * @param group group
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group(std::string group, std::string &output) {
    int res = session->call("GET", "xcatws/groups/" + group, output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get all members of group
 *
 * @param group group
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group_members(std::string group, std::vector<std::string> &output) {
    std::string response;
    if (get_group(group, response) != 0)
        return 1;

    rapidjson::Document d;
    if (d.Parse(response.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    auto c = group.c_str();
    // members are always saved as a comma-separated string
    if (d.IsObject() && d.HasMember(c) && d[c].HasMember("members") && d[c]["members"].IsString())
        utils::str_split(d[c]["members"].GetString(), ",", output);

    return 0;
}