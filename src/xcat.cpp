#include <iostream>

#include "xcat.h"

Xcat::Xcat(/* args */) {
    this->xCat = new RestClient(SESSION_TOKEN_XCAT);
}


Xcat::~Xcat() {
    delete this->xCat;
}

/******************** config ********************/
void Xcat::set_user_credentials(std::string username, std::string password) {
    xCat->set_user_credentials(username, password);
}


void Xcat::set_host_config(std::string host, std::string port) {
    xCat->set_host_config(host, port);
}


void Xcat::ssl_verify(bool sslVerify) {
    xCat->ssl_verify(sslVerify);
}


/******************** session ********************/
int Xcat::login() {
    return xCat->login();
}


void Xcat::logout() {
    xCat->logout();
}


/******************** controling ********************/

std::string Xcat::get_os_image(std::string node) {
    std::string header, response;
    xCat->get("xcatws/nodes/" + node + "/bootstate", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;

    return response;
}


void Xcat::set_os_image(std::string node, std::string osImage) {
    std::string header, response;
    xCat->put("xcatws/nodes/" + node + "/bootstate", "{\"osimage\":\"" + osImage + "\"}", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;
}


void Xcat::set_os_image_n_reboot(std::string node, std::string osImage) {
    set_os_image(node, osImage);
    reboot_node(node);
}


void Xcat::reboot_node(std::string node) {
    std::string header, response;
    xCat->put("xcatws/nodes/" + node + "/power", "{\"action\":\"reset\"}", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;
}