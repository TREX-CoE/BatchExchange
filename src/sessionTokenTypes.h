#ifndef SESSION_TOKEN_TYPES_H
#define SESSION_TOKEN_TYPES_H

#include <vector>
#include <string>

#define SESSION_TOKEN_NONE    0
#define SESSION_TOKEN_CUSTOM  1 // todo not implemented
#define SESSION_TOKEN_MEGWARE 2
#define SESSION_TOKEN_XCAT    3

struct SessionTokenTypes {
    std::vector<std::string> keysTokenType;
    std::vector<std::string> keysAccessToken;
    std::vector<std::string> keysRefreshToken;
    std::vector<std::string> keysExpireTime;
    std::vector<std::string> keysExpireDate;
};

const SessionTokenTypes SESSION_TOKEN_KEYS_MEGWARE{
    {"token_type"},
    {"access_token"},
    {"refresh_token"},
    {"expires_in"},
    {}
};

const SessionTokenTypes SESSION_TOKEN_KEYS_XCAT {
    {},
    {"token", "id"},
    {},
    {},
    {"token", "expire"}
};

#endif // SESSION_TOKEN_TYPES_H