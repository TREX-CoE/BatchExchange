#ifndef RESTCLIENT_H
#define RESTCLIENT_H

#include <string>
#include <set>
#include <curl/curl.h>

#include "httpSession.h"

class RestClient {
private:
    int         authType;
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
        const std::string httpMethod,
        const std::string &restPath,
        std::string &response,
        std::string &header,
        const std::string &postData);
    void rest_helper_post();

public:
    RestClient(const int authTypeIn);
    ~RestClient();

    int login();
    void logout();

    // setter
    void set_user_credentials(const std::string &usernameIn, const std::string &passwordIn);
    void set_host_config(const std::string &serverAddressIn, const std::string &serverPortIn);
    void ssl_verify(bool sslVerifyIn);
    void useragent(const std::string &useragent);

    // REST-calls
    int get(const std::string &restPath, std::string &response, std::string &header);
    int post(const std::string &restPath, const std::string &postData, std::string &response, std::string &header);
    int del(const std::string &restPath, std::string &response, std::string &header);
    int patch(const std::string &restPath, const std::string &postData, std::string &response, std::string &header);
    int put(const std::string &restPath, const std::string &postData, std::string &response, std::string &header);

    // information about last request
    long get_last_http_code();
    double get_last_execution_time();
    std::string get_last_url();
};

#endif // RESTCLIENT_H