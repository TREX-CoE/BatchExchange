#ifndef BOOST_PROXY_CMD_USER
#define BOOST_PROXY_CMD_USER

#include <string>
#include <vector>

namespace cw {
namespace proxy {
namespace cmd {
namespace user {


int set(const std::string& cred_file, const std::string& username, const std::vector<std::string>& scopes, const std::string& promptstr);
int remove(const std::string& cred_file, const std::string& username);


}
}
}
}


#endif /* BOOST_PROXY_CMD_USER */