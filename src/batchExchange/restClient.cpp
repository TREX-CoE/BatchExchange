#include "restClient.h"

#include <unistd.h>

#include <iostream>

#include "base64.h"
#include "curlHelper.h"

/**
 * \brief Constructor
 *
 * Constructor with necessary parameters for function. Initililizes libcurl
 * handle too.
 *
 * \param authTypeIn type of http connection (e.g. no login, token based, ...)
 *
 */
RestClient::RestClient(const int authTypeIn)
    : authType(authTypeIn) {
    this->httpSession = nullptr;

    // login credentials
    this->username.empty();
    this->password.empty();

    // server data
    this->serverAddress.empty();
    this->serverPort.empty();

    // some session settings
    this->sslVerify = true;

    // handle for http requests
    this->curl = curl_easy_init();
    this->chunk = nullptr;

    // some general settings for curl
    curl_easy_setopt(this->curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(this->curl, CURLOPT_USERAGENT, "curl");
    curl_easy_setopt(this->curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(this->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    this->lastUrlEffective.clear();
    this->lastRequestTime = 0.0;
    this->lastHttpCode = 0;
}

/**
 * \brief Destructor
 *
 * Frees session if not done yet and libcurl ressources.
 *
 */
RestClient::~RestClient() {
    this->logout();

    if (this->chunk != nullptr) {
        curl_slist_free_all(this->chunk);
    }

    if (this->curl != nullptr) {
        curl_easy_cleanup(this->curl);
    }
    this->curl = nullptr;
}

/**
 * \brief Simple setter for username an password
 *
 * \param usernameIn username for login
 * \param passwordIn password for login
 */
void RestClient::set_user_credentials(const std::string &usernameIn, const std::string &passwordIn) {
    this->username.assign(usernameIn);
    this->password.assign(passwordIn);
}

/**
 * \brief Simple setter for server settings
 *
 * \param serverAddressIn server address or dns name
 * \param serverPortIn port to communicate with (e.g. 80 for http, 443 for https)
 */
void RestClient::set_host_config(const std::string &serverAddressIn, const std::string &serverPortIn) {
    this->serverAddress.assign(serverAddressIn);
    this->serverPort.assign(serverPortIn);
}

/**
 * \brief Simple setter if ssl certificate should be checked or not
 *
 * \param sslVerifyIn true if ssl certificate should be checked
 */
void RestClient::ssl_verify(bool sslVerifyIn) {
    this->sslVerify = sslVerifyIn;
}

/**
 * \brief Simple setter user agent
 *
 * Sets the name how libcurl authenticated against the server.
 *
 * \param useragent authentication name
 */
void RestClient::useragent(const std::string &useragent) {
    curl_easy_setopt(this->curl, CURLOPT_USERAGENT, useragent.c_str());
}

/**
 * \brief Loggs in if needed
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 *         -2 no username or password
 *         -3 no host address or port
 *         -4 could not receive access token
 *         -5 already logged in
 *         -100 unknown authentication method
 */
int RestClient::login() {
    if (this->authType == SESSION_TOKEN_NONE || this->authType == SESSION_TOKEN_BASIC_AUTH)
        return 0;

    int errorCode;
    if (this->authType == SESSION_TOKEN_MEGWARE) {
        this->httpSession = new HttpSession(this->username, this->password, this->serverAddress, this->serverPort);
        this->httpSession->set_token_type(SESSION_TOKEN_MEGWARE);
        this->httpSession->set_login_path("/oauth/token");
        this->httpSession->set_logout_path("/oauth/revoke");
        this->httpSession->ssl_verify(this->sslVerify);

        errorCode = this->httpSession->login();
    } else if (this->authType == SESSION_TOKEN_XCAT) {
        this->httpSession = new HttpSession(this->username, this->password, this->serverAddress, this->serverPort);
        this->httpSession->set_token_type(SESSION_TOKEN_XCAT);
        this->httpSession->set_login_path("/xcatws/tokens");
        this->httpSession->set_logout_path("");
        this->httpSession->ssl_verify(this->sslVerify);

        errorCode = this->httpSession->login();
    } else {
        return -100;
    }

    if (errorCode != 0) {
        delete this->httpSession;
        this->httpSession = nullptr;
    }

    return errorCode;
}

/**
 * \brief Removes login tokens and frees sessions
 */
int RestClient::logout() {
    int res = 0;
    if (this->httpSession == nullptr)
        return res;

    if (this->authType == SESSION_TOKEN_MEGWARE) {
        res = this->httpSession->logout();
        delete this->httpSession;
        this->httpSession = nullptr;
    } else if (this->authType == SESSION_TOKEN_XCAT) {
        // no logout api available
        delete this->httpSession;
        this->httpSession = nullptr;
    }

    return res;
}

/**
 * \brief Represents http get request
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 */
int RestClient::get(const std::string restPath, std::string &response, std::string &header) {
    if (!curl)
        return -1;

    rest_helper_pre("GET", restPath, response, header, "");

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    rest_helper_post();

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    return static_cast<int>(this->lastHttpCode);
}

/**
 * \brief Represents http post request
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 */
int RestClient::post(const std::string restPath, const std::string &postData, std::string &response, std::string &header) {
    if (!curl) {
        return -1;
    }

    rest_helper_pre("POST", restPath, response, header, postData);

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    rest_helper_post();

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    return static_cast<int>(this->lastHttpCode);
}

/**
 * \brief Represents http delete request
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 */
int RestClient::del(const std::string restPath, std::string &response, std::string &header) {
    if (!curl) {
        return -1;
    }

    rest_helper_pre("DELETE", restPath, response, header, "");

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    rest_helper_post();

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    return static_cast<int>(this->lastHttpCode);
}

/**
 * \brief Represents http patch request
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 */
int RestClient::patch(const std::string restPath, const std::string &postData, std::string &response, std::string &header) {
    if (!curl) {
        return -1;
    }

    rest_helper_pre("PATCH", restPath, response, header, postData);

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    rest_helper_post();

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    return static_cast<int>(this->lastHttpCode);
}

/**
 * \brief Represents http put request
 *
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 */
int RestClient::put(const std::string restPath, const std::string &postData, std::string &response, std::string &header) {
    if (!curl) {
        return -1;
    }

    rest_helper_pre("PUT", restPath, response, header, postData);

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    rest_helper_post();

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    return static_cast<int>(this->lastHttpCode);
}

/**
 * \brief Prepares http request
 *
 * \param httpMethod rest method (GET, POST, DELETE, PATCH)
 * \param restPath   url path without server url and port
 * \param response   body of received server response
 * \param header     header of received server response
 * \param postData   body of outgoing request
 */
void RestClient::rest_helper_pre(
    const std::string httpMethod,
    std::string restPath,
    std::string &response,
    std::string &header,
    const std::string &postData) {
    if (restPath.at(0) != '/')
        restPath = "/" + restPath;

    const std::string url = "https://" + this->serverAddress + ":" + this->serverPort + restPath;
    std::cout << url << std::endl;
    /* curl verbosity */
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, httpMethod.c_str());

    // create request body for requests where it's needed
    if (httpMethod.compare("POST") == 0 || httpMethod.compare("PATCH") == 0 || httpMethod.compare("PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
        curl_easy_setopt(curl, CURLOPT_POST, 0);
    }

    // give libcurl pointer to write results
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, static_cast<void *>(&header));
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void *>(&response));

    // because of self signed certificate
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, this->sslVerify);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, this->sslVerify);

    // Remove a header curl would otherwise add by itself
    this->chunk = curl_slist_append(this->chunk, "Content-Type: application/json");

    switch (this->authType) {
        case SESSION_TOKEN_BASIC_AUTH:
            this->chunk = curl_slist_append(this->chunk, ("Authorization: Basic " + base64_encode(this->username + ":" + this->password)).c_str());
            break;
        case SESSION_TOKEN_MEGWARE:
            this->chunk = curl_slist_append(this->chunk, ("Authorization: Bearer " + httpSession->get_access_token()).c_str());
            break;
        case SESSION_TOKEN_XCAT:
            this->chunk = curl_slist_append(this->chunk, ("X-Auth-Token:" + httpSession->get_access_token()).c_str());
            break;
        default:
            break;
    }

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, this->chunk);
}

/**
 * \brief Some clean up and write back after request
 */
void RestClient::rest_helper_post() {
    if (this->authType == SESSION_TOKEN_BASIC_AUTH ||
        this->authType == SESSION_TOKEN_MEGWARE ||
        this->authType == SESSION_TOKEN_XCAT) {
        // cleanup
        curl_slist_free_all(this->chunk);
        this->chunk = nullptr;
    }

    char *urlEffective;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &this->lastHttpCode);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &this->lastRequestTime);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &urlEffective);
    this->lastUrlEffective = urlEffective;
}

/**
 * \brief Simple getter for http return code of last request
 *
 * \return code of last request
 */
long RestClient::get_last_http_code() {
    return this->lastHttpCode;
}

/**
 * \brief Simple getter for execution time of last request
 *
 * \return execution time of last request
 */
double RestClient::get_last_execution_time() {
    return this->lastRequestTime;
}

/**
 * \brief Simple getter for url of last request
 *
 * \return url of last request
 */
std::string RestClient::get_last_url() {
    return this->lastUrlEffective;
}