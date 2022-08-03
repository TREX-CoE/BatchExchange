/**
 * @file CXCat.h
 * @brief Header for CXCat
 *
 *
 ***********************************************/

#ifndef XCAT_H
#define XCAT_H

#include <string>

#include "restClient.h"
#include "sessionTokenTypes.h"

enum class HttpMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
};

struct ApiCallRequest {
    HttpMethod method;
    std::string body;
    std::vector<std::string> headers;  
};

struct ApiCallResponse {
    int status_code;
    std::string body;
    std::vector<std::string> headers;  
};

using http_f = std::function<void(ApiCallResponse& res, const ApiCallRequest& req)>;


// "X-Auth-Token:" + httpSession->get_access_token()
        this->httpSession->set_login_path("/xcatws/tokens");

void set_credentials() {
    _cred_header = "X-Auth-Token:" + httpSession->get_access_token()
}

void login(std::string username, std::string password) {
    _func("/xcatws/tokens?userName="+username+"&userPW="+password);
    _cred_header = "X-Auth-Token:" + httpSession->get_access_token();
}

class Xcat {
private:
	http_f _func;
    std::string _host;
    unsigned int _port;
    std::string _cred_header;
public:
	Xcat(http_f func);
    void set_host(std::string host, unsigned int port);

    void login(std::string username, std::string password);

    int get_os_images(const std::vector<std::string> &, std::string &);
    int get_os_image_names(std::vector<std::string> &);
    int get_bootstate(const std::vector<std::string> &, std::string &);
    int get_nodes(std::string &);
    int set_os_image(const std::vector<std::string> &, std::string);
    int reboot_nodes(const std::vector<std::string> &);
    int set_group_attributes(std::string, const std::string &);
    int set_node_attributes(const std::vector<std::string> &, const std::string &);
    int get_group_members(std::string group, std::vector<std::string> &output);
    int get_group_names(std::vector<std::string> &);
    int get_group(std::string, std::string &);
};

#endif  // XCAT_H