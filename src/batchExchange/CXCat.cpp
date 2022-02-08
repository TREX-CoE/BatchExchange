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
    if (session->call("GET", "xcatws/nodes", output) != 0)
        return 1;

    if (utils::check_errors(output) != 0)
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

    if (session->call("GET", "xcatws/osimages/" + imageRange, output) != 0)
        return 1;

    if (utils::check_errors(output) != 0)
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
 * @param filter  filter
 * @param output  output
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
    if (session->call("GET", "xcatws/nodes/" + nodeRange + "/bootstate", output) != 0)
        return 1;

    if (utils::check_errors(output) != 0)
        return 1;

    return 0;
}

/**
 * @brief Set os image
 * 
 * @param filter  filter
 * @param output  output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_os_image(const std::vector<std::string> &filter, std::string osImage) {
    if (!filter.size() || !osImage.length())
        return 1;
    std::string response;
    if (session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/bootstate", response, "{\"osimage\":\"" + osImage + "\"}") != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

/**
 * @brief Reboot nodes
 * 
 * @param filter  filter
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::reboot_nodes(const std::vector<std::string> &filter) {
    if (!filter.size())
        return 1;
    std::string response;
    if (session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/power", response, "{\"action\":\"reset\"}") != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

int CXCat::set_group_attributes(std::string filter, const std::string &attributes) {
    if (!filter.length() || !attributes.length())
        return 1;

    return 0;
}

int CXCat::set_postscript(const std::vector<std::string> &filter, std::string postscript) {
    if (!filter.size() || !postscript.length())
        return 1;

    return 0;
}

int CXCat::get_groups(const std::vector<std::string> &filter, std::string &output) {
    return 0;
}

int CXCat::get_group_members(const std::vector<std::string> &filter, std::string &output) {
    return 0;
}