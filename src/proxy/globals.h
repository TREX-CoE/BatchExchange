#ifndef BOOST_PROXY_GLOBALS
#define BOOST_PROXY_GLOBALS

#include "proxy/credentials.h"

namespace cw {
namespace globals {

void init(const cw::helper::credentials::dict& creds, const std::string& cred_file);

cw::helper::credentials::dict creds();
void creds(cw::helper::credentials::dict _creds);
std::error_code creds_get(const std::string& user, const std::string& pass, std::set<std::string>& scopes);
std::error_code creds_check(const std::string& user, const std::string& pass, const std::set<std::string>& scopes);

const std::string& cred_file();

}
}

#endif /* BOOST_PROXY_GLOBALS */