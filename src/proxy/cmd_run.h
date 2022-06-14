#ifndef BOOST_PROXY_CMD_RUN
#define BOOST_PROXY_CMD_RUN

#include <string>

namespace cw {
namespace proxy {
namespace cmd {
int run(const std::string& cred, int threads, const std::string& host, int port, const std::string& cert, const std::string& priv, const std::string& dh, bool force_ssl, bool no_ssl, bool no_websocket);
}
}
}

#endif /* BOOST_PROXY_CMD_RUN */