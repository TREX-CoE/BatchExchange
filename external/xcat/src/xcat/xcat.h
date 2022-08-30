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
    no_auth,
    api_error,
    get_nodes_failed,
    get_groups_failed,
    get_bootstate_failed,
    set_bootstate_failed,
    get_osimages_failed,
    set_group_attributes_failed,
    set_nextboot_failed,
    set_powerstate_failed,
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

struct XcatError {
    std::error_code ec;
    int error_code;
    std::string msg;
};

using http_f = std::function<void(ApiCallRequest req, std::function<void(ApiCallResponse)> resp)>;

struct NodeInfo {
    std::string name;
    std::string postscripts;
    std::string postbootscripts;
    std::string installnic;
    std::string primarynic;
    std::string mac;
    std::vector<std::string> groups;
    std::map<std::string, std::string> extra;
};

struct GroupInfo {
    std::string name;
    std::string mgt;
    std::string netboot;
    std::vector<std::string> members;
};

struct OsimageInfo {
    std::string name;
    std::string profile;
    std::string osname;
    std::string osarch;
    std::string osvers;
    std::string provmethod;
};

class Xcat {
private:
	http_f _func;
    std::string _token;
    unsigned long int _expires;
    std::string _username;
    std::string _password;

    ApiCallRequest add_auth(ApiCallRequest req, bool has_query_params);
public:
	Xcat(http_f func);

    void set_token(std::string token, unsigned long expires);
    void set_credentials(std::string username, std::string password);

    void get_token(std::function<void(std::string token, unsigned long int expires, XcatError ec)> cb);

    bool check_auth();

    void get_nodes(std::function<void(std::map<std::string, NodeInfo>, XcatError ec)> cb);
    void get_groups(const std::vector<std::string> &filter, std::function<void(std::map<std::string, GroupInfo>, XcatError ec)> cb);
    void get_osimages(const std::vector<std::string> &filter, std::function<void(std::map<std::string, OsimageInfo>, XcatError ec)> cb);
    void get_bootstate(const std::vector<std::string> &filter, std::function<void(std::map<std::string, std::string>, XcatError ec)> cb);
    void set_powerstate(const std::vector<std::string> &filter, std::string action, std::function<void(std::string, XcatError ec)> cb);
    void set_nextboot(const std::vector<std::string> &filter, std::string order, std::function<void(std::string, XcatError ec)> cb);
    void set_bootstate(const std::vector<std::string> &filter, std::string osimage, std::function<void(std::string, XcatError ec)> cb);
    void set_group_attributes(const std::vector<std::string> &filter, const std::map<std::string, std::string>& attrs, std::function<void(std::string, XcatError ec)> cb);
}; 


}

namespace std
{
  template <>
  struct is_error_code_enum<xcat::error> : true_type {};
}


#endif  // XCAT_H
