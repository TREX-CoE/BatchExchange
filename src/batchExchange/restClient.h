#ifndef RESTCLIENT_H
#define RESTCLIENT_H

#include <curl/curl.h>

#include <set>
#include <string>

#include "httpSession.h"

class RestClient {
   private:
    int authType;
    HttpSession *httpSession;

    // login credentials
    std::string username;
    std::string password;

    // server data
    std::string serverAddress;
    std::string serverPort;

    // for self signed certificates
    bool sslVerify;

    // handle for http requests
    CURL *curl;
    struct curl_slist *chunk;

    std::string lastUrlEffective;
    double lastRequestTime;
    long lastHttpCode;

    void rest_helper_pre(
        const std::string,
        std::string,
        std::string &,
        std::string &,
        const std::string &);
    void rest_helper_post();

    const std::vector<std::string> httpMethods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE"};

   public:
    RestClient(const int);
    ~RestClient();

    int login();
    int logout();

    // setter
    void set_user_credentials(const std::string &, const std::string &);
    void set_host_config(const std::string &, const std::string &);
    void ssl_verify(bool);
    void useragent(const std::string &);

    // REST-calls
    int get(const std::string &, std::string &, std::string &);
    int post(const std::string &, const std::string &, std::string &, std::string &);
    int del(const std::string &, std::string &, std::string &);
    int patch(const std::string &, const std::string &, std::string &, std::string &);
    int put(const std::string &, const std::string &, std::string &, std::string &);
    int call(std::string, const std::string &, std::string &, const std::string & = "");
    // information about last request
    long get_last_http_code();
    double get_last_execution_time();
    std::string get_last_url();
};

#endif  //RESTCLIENT_H