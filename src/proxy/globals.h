#ifndef BOOST_PROXY_GLOBALS
#define BOOST_PROXY_GLOBALS

#include "proxy/credentials.h"

namespace cw {
namespace globals {

void init(const cw::helper::credentials::dict& creds, const std::string& cred_file);

cw::helper::credentials::dict creds();
void creds(cw::helper::credentials::dict _creds);
bool creds_check(string_view header, const std::set<std::string>& scopes);

const std::string& cred_file();

}
}

#endif /* BOOST_PROXY_GLOBALS */