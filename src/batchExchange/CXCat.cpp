#include "CXCat.h"

#include <iostream>

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

void CXCat::logout() {
    session->logout();
}

std::string CXCat::get_os_image(std::string node) {
    std::string header, response;
    // session->get("xcatws/images/", response, header);
    session->get("xcatws/nodes/" + node + "/bootstate", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;

    return response;
}

void CXCat::set_os_image(std::string node, std::string osImage) {
    std::string header, response;
    session->put("xcatws/nodes/" + node + "/bootstate", "{\"osimage\":\"" + osImage + "\"}", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;
}

void CXCat::set_os_image_n_reboot(std::string node, std::string osImage) {
    set_os_image(node, osImage);
    reboot_node(node);
}

void CXCat::reboot_node(std::string node) {
    std::string header, response;
    session->put("xcatws/nodes/" + node + "/power", "{\"action\":\"reset\"}", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;
}