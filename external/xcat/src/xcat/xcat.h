#ifndef XCAT_H
#define XCAT_H

#include <string>
#include <system_error>
#include <functional>
#include <vector>
#include <map>

namespace xcat {

enum class error {
    login_failed = 1,
    no_token,
    api_error,
    get_nodes_failed,
    get_groups_failed,
};


const std::error_category& error_category() noexcept;

std::error_code make_error_code(error e);


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
    HttpMethod method = HttpMethod::GET;
    std::string uri;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct ApiCallResponse {
    unsigned int status_code = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    std::error_code ec;
};

using http_f = std::function<void(ApiCallRequest req, std::function<void(ApiCallResponse)> resp)>;

struct TokenInfo {
    std::string token;
    unsigned long int expires;
};

struct NodeInfo {
    std::string name;
    std::string postscripts;
    std::string postbootscripts;
    std::string installnic;
    std::string primarynic;
    std::string mac;
    std::string groups;
};

struct GroupInfo {
    std::string name;
    std::string mgt;
    std::string netboot;
    std::vector<std::string> members;
};

class Xcat {
private:
	http_f _func;
    std::string _host;
    unsigned int _port;
    std::string _token;
public:
	Xcat(http_f func);
    void set_host(std::string host, unsigned int port);

    void login(std::string username, std::string password, std::function<void(TokenInfo token, std::error_code ec)> cb);
    void set_token(std::string token);

    void get_nodes(std::function<void(std::map<std::string, NodeInfo>, std::error_code ec)> cb);
    void get_groups(std::string group, std::function<void(std::map<std::string, GroupInfo>, std::error_code ec)> cb);
    void get_os_images(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb);
    void get_bootstate(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb);
    void power_nodes(const std::vector<std::string> &filter, std::string action, std::function<void(std::string, std::error_code ec)> cb);
    void set_bootstate(const std::vector<std::string> &filter, std::string osimage, std::function<void(std::string, std::error_code ec)> cb);
    void set_group_attributes(const std::vector<std::string> &filter, const std::map<std::string, std::string>& attrs, std::function<void(std::string, std::error_code ec)> cb);
}; 


}

namespace std
{
  template <>
  struct is_error_code_enum<xcat::error> : true_type {};
}


#endif  // XCAT_H
