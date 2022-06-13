#ifndef BOOST_PROXY_CREDENTIALS
#define BOOST_PROXY_CREDENTIALS

#include <string>
#include <map>
#include <set>

#include <boost/utility/string_view.hpp>
#include "shared/http.h"

namespace cw {
namespace helper {
namespace credentials {

struct user_data {
    std::set<std::string> scopes;
    std::string salt;
    std::string hash;
};

using dict = std::map<std::string, user_data>;

void read(dict& creds, const std::string& s);

void write(const dict& creds, std::string& out);

void set_user(credentials::dict& creds, boost::string_view user, std::set<std::string> scopes, boost::string_view password);

dict::const_iterator check_header(const dict& creds, boost::string_view header);

}
}
}

#endif /* BOOST_PROXY_CREDENTIALS */