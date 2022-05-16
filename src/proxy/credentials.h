#ifndef BOOST_PROXY_CREDENTIALS
#define BOOST_PROXY_CREDENTIALS

#include <string>
#include <map>
#include <set>

#include "shared/string_view.h"
#include "shared/http.h"

namespace cw {
namespace credentials {

struct user_data {
    std::set<std::string> scopes;
    std::string salt;
    std::string hash;
};

using dict = std::map<std::string, user_data>;

void read(dict& creds, std::istream& in);

void write(const dict& creds, std::ostream &out);

void set_user(credentials::dict& creds, string_view user, std::set<std::string> scopes, string_view password);

dict::const_iterator check_header(const dict& creds, string_view header);

}
}

#endif /* BOOST_PROXY_CREDENTIALS */