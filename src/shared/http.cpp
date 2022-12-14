#include "shared/http.h"
#include "shared/base64.h"

#include <iostream>

static boost::string_view basic = "Basic ";
static boost::string_view del = ":";

namespace cw {
namespace http {

bool parse_auth_header(boost::string_view header, std::string& user, std::string& pass) {
    if (header.rfind(basic.data(), 0) == 0) {
        std::string login = base64::decode(header.substr(basic.size()));
        const auto idx = login.find(del.data());
        if (idx != std::string::npos) {
            user = login.substr(0, idx);
            pass = login.substr(idx+del.size());
            return true;
        }
    }
    return false;
}

}
}

