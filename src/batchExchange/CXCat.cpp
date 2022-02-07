#include "CXCat.h"

#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "utils.h"

CXCat::CXCat(std::string host, std::string port, std::string username, std::string password, bool sslVerify) {
    session = new RestClient(SESSION_TOKEN_XCAT);
    session->set_user_credentials(username, password);
    session->set_host_config(host, port);
    session->ssl_verify(sslVerify);
}

CXCat::~CXCat() {
    delete session;
}

int CXCat::login() {
    return session->login();
}

int CXCat::logout() {
    return session->logout();
}

int CXCat::get_nodes(std::string &output) {
    if (session->call("GET", "xcatws/nodes", output) != 0)
        return 1;

    if (utils::check_errors(output) != 0)
        return 1;

    return 0;
}

int CXCat::get_os_images(std::vector<std::string> &images, std::string &output) {
    std::string response, imageRange = "ALLRESOURCES";

    if (images.size())
        imageRange = utils::join_vector_to_string(images, ",");

    if (session->call("GET", "xcatws/osimages/" + imageRange, output) != 0)
        return 1;

    if (utils::check_errors(output) != 0)
        return 1;

    return 0;
}

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

int CXCat::get_bootstate(std::vector<std::string> &nodes, std::string &output) {
    // this uri does not provide a way to query all nodes at once -> fetch all nodes and join to {noderange}
    std::string nodeRange = "";
    if (nodes.size())
        nodeRange = utils::join_vector_to_string(nodes, ",");
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

int CXCat::set_os_image(std::vector<std::string> &nodes, std::string osImage) {
    if (!nodes.size())
        return 1;
    std::string response;
    if (session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(nodes, ",") + "/bootstate", response, "{\"osimage\":\"" + osImage + "\"}") != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

int CXCat::reboot_nodes(std::vector<std::string> &nodes) {
    if (!nodes.size())
        return 1;
    std::string response;
    if (session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(nodes, ",") + "/power", response, "{\"action\":\"reset\"}") != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}