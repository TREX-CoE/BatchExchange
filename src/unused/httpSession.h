#ifndef HTTPSESSTION_H
#define HTTPSESSTION_H

#include <string>
#include <vector>
#include <ctime>
#include <curl/curl.h>

#include "sessionTokenTypes.h"

#define HTTPSESSTION_TYPE_TIMESTAMP 0
#define HTTPSESSTION_TYPE_STRING    1
#define HTTPSESSTION_TYPE_INT       2

class SessionToken {
private:
    std::vector<std::string> keysTokenType;
    std::vector<std::string> keysAccessToken;
    std::vector<std::string> keysRefreshToken;
    std::vector<std::string> keysExpireTime;
    std::vector<std::string> keysExpireDate;

    std::string dateParseDescr;

    // token data
    std::string tokenType;
    std::string accessToken;
    std::string refreshToken;
    int expireTime; // in sec
    time_t expireDate;

    int read_token_helper(const std::string &token, void *value, std::vector<std::string> &keylist, int type);

public:
    SessionToken();
    ~SessionToken();

    void set_keys_token_type(const std::vector<std::string> &keysTokenTypeIn);
    void set_keys_access_token(const std::vector<std::string> &keysAccessTokenIn);
    void set_keys_refresh_token(const std::vector<std::string> &keysRefreshTokenIn);
    void set_keys_expire_time(const std::vector<std::string> &keysExpireTimeIn);
    void set_keys_expire_date(const std::vector<std::string> &keysExpireDateIn);
    void set_keys_by_token_type(const SessionTokenTypes token);

    void set_date_parse_descr(std::string formatDesc);

    int read_token(const std::string &token);

    bool token_expired();
    int token_time_to_expire();

    std::string get_token_type();
    std::string get_access_token();
    std::string get_refresh_token();
    int get_expire_time();
    time_t get_expire_date();
};


class HttpSession {
private:
    // login credentials
    const std::string username;
    const std::string password;
    std::string clientId;

    // server data
    const std::string serverAddress;
    const std::string serverPort;

    //
    std::string loginPath;
    std::string logoutPath;

    // check ssl certificate
    bool sslVerify;

    SessionToken sessionToken;
    int tokenType;

    // handle for http requests
    CURL *curl;

    bool loggedIn;

public:
    HttpSession(
        const std::string &usernameIn,
        const std::string &passwordIn,
        const std::string &serverAddressIn,
        const std::string &serverPortIn
    );
    ~HttpSession();

    void ssl_verify(bool verfiy);

    int set_token_type(int tokenTypeIn, const SessionTokenTypes *sessionTokenTypes = nullptr);
    void set_date_parse_descr(const std::string formatDesc);

    void set_login_path(const std::string loginPathIn);
    void set_logout_path(const std::string logoutPathIn);

    std::string get_access_token();

    int login();
    int logout();
};

#endif //HTTPSESSTION_H