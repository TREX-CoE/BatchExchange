#include "shared/http.h"
#include "shared/base64.h"

static const char* basic = "Basic ";
static const char* delimiter = ":";

namespace cw {
namespace http {

bool parse_auth_header(string_view header, std::string& user, std::string& pass) {
    if (header.rfind(basic, 0) == 0) {
        std::string login = base64::decode(header.substr(sizeof(basic)-1));
        const auto idx = login.find(delimiter);
        if (idx != std::string::npos) {
            user = login.substr(0, idx);
            pass = login.substr(idx+sizeof(delimiter)-1);
            return true;
        }
    }
    return false;
}

}
}

