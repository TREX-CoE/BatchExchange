#ifndef BOOST_PROXY_CREDS
#define BOOST_PROXY_CREDS

#include "proxy/credentials.h"

namespace cw {
namespace creds {

void init(const cw::helper::credentials::dict& creds);
const cw::helper::credentials::dict& get();

}
}

#endif /* BOOST_PROXY_CREDS */