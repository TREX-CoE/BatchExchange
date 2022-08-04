#ifndef XCAT_H
#define XCAT_H

#include <string>
#include <system_error>

namespace xcat {

enum class error {
    login_failed = 1,
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
    std::vector<std::string> headers;  
};

struct ApiCallResponse {
    unsigned int status_code = 0;
    std::string body;
    std::vector<std::string> headers;  
};

using http_f = std::function<void(ApiCallResponse& res, const ApiCallRequest& req)>;

class Xcat {
private:
	http_f _func;
    std::string _host;
    unsigned int _port;
    std::string _cred_header;
public:
	Xcat(http_f func);
    void set_host(std::string host, unsigned int port);

    std::function<bool(std::string&)> login(std::string username, std::string password);
    void set_token(std::string token);

    std::function<bool(std::string&)> get_nodes();



    int get_os_images(const std::vector<std::string> &, std::string &);
    int get_os_image_names(std::vector<std::string> &);
    int get_bootstate(const std::vector<std::string> &, std::string &);
    int set_os_image(const std::vector<std::string> &, std::string);
    int reboot_nodes(const std::vector<std::string> &);
    int set_group_attributes(std::string, const std::string &);
    int set_node_attributes(const std::vector<std::string> &, const std::string &);
    int get_group_members(std::string group, std::vector<std::string> &output);
    int get_group_names(std::vector<std::string> &);
    int get_group(std::string, std::string &);
};

}

namespace std
{
  template <>
  struct is_error_code_enum<xcat::error> : true_type {};
}


#endif  // XCAT_H