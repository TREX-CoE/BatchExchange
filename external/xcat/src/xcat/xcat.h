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


struct BootState {
    std::string osImage;
};

using http_f = std::function<void(ApiCallResponse& res, const ApiCallRequest& req)>;

class Xcat {
private:
	http_f _func;
    std::string _host;
    unsigned int _port;
    std::string _token;
public:
	Xcat(http_f func);
    void set_host(std::string host, unsigned int port);

    std::function<bool(std::string&, std::error_code& ec)> login(std::string username, std::string password);
    void set_token(std::string token);

    std::function<bool(std::string&, std::error_code& ec)> get_nodes();
    std::function<bool(std::string&, std::error_code& ec)> get_os_images(const std::vector<std::string> &filter);
    std::function<bool(std::string&, std::error_code& ec)> get_bootstate(const std::vector<std::string> &filter);
    std::function<bool(std::error_code& ec)> set_os_image(const std::vector<std::string> &filter, std::string osImage);
    std::function<bool(std::string&, std::error_code& ec)> power_nodes(const std::vector<std::string> &filter);
    std::function<bool(std::string&, std::error_code& ec)> set_bootstate(const std::vector<std::string> &filter, BootState state);
    std::function<bool(std::string&, std::error_code& ec)> set_group_attributes(const std::vector<std::string> &filter);
    std::function<bool(std::string&, std::error_code& ec)> get_groups(std::string group);
};

}

namespace std
{
  template <>
  struct is_error_code_enum<xcat::error> : true_type {};
}


#endif  // XCAT_H
