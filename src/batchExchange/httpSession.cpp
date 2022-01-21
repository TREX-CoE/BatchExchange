#include <cctype>
#include <rapidjson/document.h>

#include <iostream>
namespace json = rapidjson;

#include "httpSession.h"
#include "curlHelper.h"

///////////////////////// SessionToken /////////////////////////

/**
 * \brief Standard constructor
 */
SessionToken::SessionToken() {
    // nothing todo
}


/**
 * \brief Standard destructor
 */
SessionToken::~SessionToken() {
    // nothing todo
}


/**
 * \brief Simple setter
 * 
 * \param keysTokenTypeIn contains keys of json file where to find the token type ["token", "tokenType"]
 */
void SessionToken::set_keys_token_type(const std::vector<std::string> &keysTokenTypeIn) {
    this->keysTokenType = keysTokenTypeIn;
}


/**
 * \brief Simple setter
 * 
 * \param keysAccessTokenIn contains keys of json file where to find the access token ["token", "accessToken"]
 */
void SessionToken::set_keys_access_token(const std::vector<std::string> &keysAccessTokenIn) {
    this->keysAccessToken = keysAccessTokenIn;
}


/**
 * \brief Simple setter
 * 
 * \param keysRefreshTokenIn contains keys of json file where to find the refresh token ["token", "refreshToken"]
 */
void SessionToken::set_keys_refresh_token(const std::vector<std::string> &keysRefreshTokenIn) {
    this->keysRefreshToken = keysRefreshTokenIn;
}


/**
 * \brief Simple setter
 * 
 * \param keysExpireTimeIn contains keys of json file where to find the expire time ["token", "time"]
 */
void SessionToken::set_keys_expire_time(const std::vector<std::string> &keysExpireTimeIn) {
    this->keysExpireTime = keysExpireTimeIn;
}


/**
 * \brief Simple setter
 * 
 * \param keysExpireDateIn contains keys of json file where to find the expire date ["token", "date"]
 */
void SessionToken::set_keys_expire_date(const std::vector<std::string> &keysExpireDateIn) {
    this->keysExpireDate = keysExpireDateIn;
}


/**
 * \brief Sets keys to extract session token more easyly
 * 
 * \param token struct with json keys for token attributes
 */
void SessionToken::set_keys_by_token_type(const SessionTokenTypes token) {
    set_keys_token_type(token.keysTokenType);
    set_keys_access_token(token.keysAccessToken);
    set_keys_refresh_token(token.keysRefreshToken);
    set_keys_expire_time(token.keysExpireTime);
    set_keys_expire_date(token.keysExpireDate);
}


/**
 * \brief Wrapper for reading token data from json object
 * 
 * \param token the token data as json containted in a string
 * 
 * \return error code
 */
int SessionToken::read_token(const std::string &token) {
    int errorCode;
    errorCode = read_token_helper(token, &tokenType, keysTokenType, HTTPSESSTION_TYPE_STRING);
    if (errorCode != 0) return errorCode;
    errorCode = read_token_helper(token, &accessToken,  keysAccessToken,  HTTPSESSTION_TYPE_STRING);
    if (errorCode != 0) return errorCode;
    errorCode = read_token_helper(token, &refreshToken, keysRefreshToken, HTTPSESSTION_TYPE_STRING);
    if (errorCode != 0) return errorCode;
    errorCode = read_token_helper(token, &expireTime,   keysExpireTime,   HTTPSESSTION_TYPE_INT);
    // work with expire time is more general than time
    // makes it easier to determine when token is expired
    if (expireTime != -1) {
        expireDate = time(nullptr) + expireTime;
    }
    if (errorCode != 0) return errorCode;
    errorCode = read_token_helper(token, &expireDate,   keysExpireDate,   HTTPSESSTION_TYPE_TIMESTAMP);

    return errorCode;
}


/**
 * \brief Resturns if token is expired
 * 
 * \return simple bool true == expired
 */
bool SessionToken::token_expired() {
    return token_time_to_expire() <= 0;
}


/**
 * \brief Delivers time in seconds when how long the token is valid
 * 
 * \return time in seconds
 */
int SessionToken::token_time_to_expire() {
    return expireTime - time(nullptr);
}


/**
 * \brief Setter for data format.
 * 
 * Must have a format like it is described in strtime.
 * https://www.cplusplus.com/reference/ctime/strftime/
 * 
 * \param formatDesc strtime like date description
 */
void SessionToken::set_date_parse_descr(std::string formatDesc) {
    this->dateParseDescr = formatDesc;
}


/**
 * \brief Simple getter
 * 
 * \return Type of the token e.g X-Auth, Bearer, ...
 */
std::string SessionToken::get_token_type() {
    return this->tokenType;
}


/**
 * \brief Simple getter
 * 
 * \return the access token itself
 */
std::string SessionToken::get_access_token() {
    return this->accessToken;
}


/**
 * \brief Simple getter
 * 
 * \return a refresh token to request a new access token
 */
std::string SessionToken::get_refresh_token() {
    return this->refreshToken;
}


/**
 * \brief Simple getter
 * 
 * \return expire time of the access token in seconds
 */
int SessionToken::get_expire_time() {
    return this->expireTime;
}


/**
 * \brief Simple getter
 * 
 * \return expire date of the access token as unix timestamp
 */
time_t SessionToken::get_expire_date() {
    return this->expireDate;
}


///// private

/**
 * \brief Reads sinlge token vars from the response of the server
 * 
 * \param token server response with session token in json format
 * \param value member var for extracted value
 * \param type data type of the member var to cast void* to the right pointer
 * 
 * \return -1 json couldn't be parsed
 *         -2 key not found
 *         -3 key is not an object
 *         -4 value has wrong data type
 *         -10 parsing error of date/time
 *         -100 unknown data type
 */
int SessionToken::read_token_helper(const std::string &token, void *value, std::vector<std::string> &keylist, int type) {
    // clear if new token doesn't contain value
    // or an error occurs while parsing
    if (type == HTTPSESSTION_TYPE_STRING) {
        (static_cast<std::string *>(value))->clear();
    } else if (type == HTTPSESSTION_TYPE_INT) {
        *(static_cast<int *>(value)) = -1;
    } else if (type == HTTPSESSTION_TYPE_TIMESTAMP) {
        // Set sec, min, hour, ... to zero in case the format does not provide those
        expireDate = 0;
    } else {
        return -100;
    }

    // parse string to json
    json::Document tokenData;
    tokenData.Parse(token.c_str());

    // catch error while parsing
    if (!tokenData.IsObject()) {
        return -1;
    }

    // trick for depth search, see loop below
    // (no public standard constuctor vor Value class only copy constructor)
    json::Value v = tokenData.GetObject();
    json::Value &tmpObject = v;

    // step over keys that represents the json objects
    if (keylist.size()) {
        std::vector<std::string>::iterator it;
        for (it = keylist.begin(); it != keylist.end()-1; ++it) {
            const char* key = it->c_str();
            if (!tmpObject.HasMember(key)) {
                return -2;
            }
            if (!tmpObject[key].IsObject()) {
                return -3;
            }
            tmpObject = tmpObject[key].GetObject();
        }
        
        // write value in member var
        const char *key = it->c_str();
        if (type == HTTPSESSTION_TYPE_STRING) {
            if (!tmpObject[key].IsString()) {
                return -4;
            }
            *static_cast<std::string *>(value) = tmpObject[key].GetString();
        } else if (type == HTTPSESSTION_TYPE_INT) {
            if (!tmpObject[key].IsInt()) {
                return -4;
            }
            *static_cast<int *>(value) = tmpObject[key].GetInt();
        } else if (type == HTTPSESSTION_TYPE_TIMESTAMP) {
            if (!tmpObject[key].IsString()) {
                return -4;
            }

            // parse date in tm data structure
            std::tm tmp;
            const char* res = strptime(tmpObject[key].GetString(), dateParseDescr.c_str(), &tmp);
            if (res == nullptr) {
                //std::cout << "Parse error" << std::endl;
                return -10;
            }
            *(static_cast<time_t *>(value)) = mktime(&tmp);
        }
    }

    return 0;
}

///////////////////////// HttpSession /////////////////////////

/**
 * \brief Constructor
 * 
 * Constructor with necessary parameters for function. Initililizes libcurl
 * handle too.
 * 
 * \param usernameIn        login name of user
 * \param passwordIn        login password of user
 * \param serverAddressIn   url of server
 * \param serverPortIn      port of server
 * 
 */
HttpSession::HttpSession(
        const std::string &usernameIn,
        const std::string &passwordIn,
        const std::string &serverAddressIn,
        const std::string &serverPortIn)
    : username(usernameIn)
    , password(passwordIn)
    , serverAddress(serverAddressIn)
    , serverPort(serverPortIn) {

    this->clientId = "wf_" + usernameIn;
    this->loginPath = "";
    this->logoutPath = "";

    this->tokenType = SESSION_TOKEN_CUSTOM;

    // curl things
    this->curl = curl_easy_init();
    this->loggedIn = false;

    // http header
    this->sslVerify = true;
}


/**
 * \brief Destructor
 * 
 * Frees session if not done yet and libcurl ressources.
 * 
 */
HttpSession::~HttpSession() {
    switch (this->tokenType) {
    case SESSION_TOKEN_XCAT:
        // do nothing
        // it isn't possible to logout @ xCAT
        break;
    
    default:
        // auto logout if the explicit logout was forgotten
        if (this->loggedIn) {
            logout();
        }
        break;
    }

    if (curl) {
        curl_easy_cleanup(curl);
    }
    curl = nullptr;
}


/**
 * \brief Sets keys to extract session token more easyly
 * 
 * \param tokenTypeIn defines which type of token should be used
 * \param sessionTokenTypes struct with json keys for token attributes
 */
int HttpSession::set_token_type(int tokenTypeIn, const SessionTokenTypes *sessionTokenTypes) {
    this->tokenType = tokenTypeIn;
    
    switch (this->tokenType) {
    case SESSION_TOKEN_CUSTOM:
        sessionToken.set_keys_by_token_type(*sessionTokenTypes);
        break;    
    case SESSION_TOKEN_MEGWARE:
        sessionToken.set_keys_by_token_type(SESSION_TOKEN_KEYS_MEGWARE);
        break;
    case SESSION_TOKEN_XCAT:
        sessionToken.set_keys_by_token_type(SESSION_TOKEN_KEYS_XCAT);
        break;
    
    default:
        return -1;
    }

    return 0;
}


/**
 * \brief Setter for data format.
 * 
 * Must have a format like it is described in strtime.
 * https://www.cplusplus.com/reference/ctime/strftime/
 * 
 * \param formatDesc strtime like date description
 */
void HttpSession::set_date_parse_descr(const std::string formatDesc) {
    sessionToken.set_date_parse_descr(formatDesc);
}


/**
 * \brief Defines the URL path for login
 * 
 * \param loginPathIn URL path (leading / is needed)
 */
void HttpSession::set_login_path(const std::string loginPathIn) {
    this->loginPath = loginPathIn;
}


/**
 * \brief Defines the URL path for logout
 * 
 * \param logoutPathIn URL path (leading / is needed)
 */
void HttpSession::set_logout_path(const std::string logoutPathIn) {
    this->logoutPath = logoutPathIn;
}


/**
 * \brief Simple setter if ssl certificate should be checked or not
 * 
 * \param verfiy true if ssl certificate should be checked
 */
void HttpSession::ssl_verify(bool verfiy) {
    this->sslVerify = verfiy;
}


/**
 * \brief Simple getter
 * 
 * \return the access token itself
 */
std::string HttpSession::get_access_token() {
    return sessionToken.get_access_token();
}


/**
 * \brief Gets authentification token
 * 
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 *         -1 no libcurl handle
 *         -2 no username or password
 *         -3 no host address or port
 *         -4 could not receive access token
 *         -5 already logged in
 *         -10 could'n extract token
 *         -100 unknown session type
 * 
 * \param loginPathIn REST path to login endpoint (leading / is needed e.g. "/token")
 */
int HttpSession::login() {
    if (!curl) {
        return -1;
    }

    if (this->loggedIn) {
        return -5;
    }

    if (this->username.length() == 0 || this->password.length() == 0) {
        return -2;
    }

    if (this->serverAddress.length() == 0 || this->serverPort.length() == 0) {
        return -3;
    }

    std::string url;
    switch (this->tokenType) {
    case SESSION_TOKEN_MEGWARE:
        url = "https://" + this->serverAddress + ":" + this->serverPort + this->loginPath;
        break;
    case SESSION_TOKEN_XCAT:
        url = "https://" + this->serverAddress + ":" + this->serverPort + this->loginPath + "?userName=" + this->username + "&userPW=" + this->password;
        break;
    case SESSION_TOKEN_CUSTOM:
        break;

    default:
        break;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // because of self signed certificate
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, this->sslVerify);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, this->sslVerify);

    // send all data to this function
    std::string reqData;
    std::string *pReqData = &reqData;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)pReqData);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    // fill in post field of http request with login credentials
    std::string postfields;
    switch (this->tokenType) {
    case SESSION_TOKEN_CUSTOM:
        // todo not implemented
        break;
    case SESSION_TOKEN_MEGWARE:
        postfields = "grant_type=password&client_id=" + this->clientId + "&username=" + this->username + "&password=" + this->password;
        break;
    case SESSION_TOKEN_XCAT:
        postfields = "";
        break;
    default:
        return -100;
    }

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());

    // Remove a header curl would otherwise add by itself
    struct curl_slist *chunk = NULL;
    switch (this->tokenType) {
    case SESSION_TOKEN_CUSTOM:
        break;
    case SESSION_TOKEN_MEGWARE:
        chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
        chunk = curl_slist_append(chunk, ("Authorization: Basic " + this->username + ":" + this->password).c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        break;
    case SESSION_TOKEN_XCAT:
        chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
        chunk = curl_slist_append(chunk, ("Authorization: Basic " + this->username + ":" + this->password).c_str());
        break;
    default:
        return -100;
    }
    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    // cleanup
    curl_slist_free_all(chunk);

    // check if http request has succeeded
    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    // check http return code of request
    long http_code = 0;
    curlErrorCode = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200 && curlErrorCode != CURLE_OK) {
        return http_code;
    }

    if (sessionToken.read_token(reqData) != 0) {
        // couldn't extract token
        return -10;
    }

    this->loggedIn = true;
    return curlErrorCode;
}


/**
 * \brief Frees authentification token
 * 
 * \return 0-100 error codes from libcurl
 *         >100 http error codes
 */
int HttpSession::logout() {
    std::string url = "https://" + this->serverAddress + ":" + this->serverPort + this->logoutPath;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    std::string postfields;
    switch (tokenType) {
    case SESSION_TOKEN_CUSTOM:
        // todo not implemented
        break;
    case SESSION_TOKEN_MEGWARE:
        postfields = "client_id=" + this->clientId + "&token=" + sessionToken.get_access_token();
        break;
    case SESSION_TOKEN_XCAT:
        this->loggedIn = false;
        return 0;
    
    default:
        break;
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());

    // Remove a header curl would otherwise add by itself
    struct curl_slist *chunk = NULL;
    chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // send http request
    CURLcode curlErrorCode;
    curlErrorCode = curl_easy_perform(curl);

    // cleanup
    curl_slist_free_all(chunk);

    if (curlErrorCode != CURLE_OK) {
        return curlErrorCode;
    }

    // check http return code of request
    long http_code = 0;
    curlErrorCode = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200 && curlErrorCode != CURLE_OK) {
        return http_code;
    }

    this->loggedIn = false;
    return curlErrorCode;
}