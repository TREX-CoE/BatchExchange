#ifndef BOOST_PROXY_SALT_HASH
#define BOOST_PROXY_SALT_HASH

#include "shared/salt_hash.h"
#include "shared/string_view.h"
#include "shared/obfuscator.h"

namespace cw {
namespace proxy {

static inline std::string salt_hash(string_view salt, string_view input) {
    return cw::helper::salt_hash(cw::helper::obfuscator<sizeof(PEPPER), PEPPER_XOR, int>(PEPPER), salt, input);
}

}
}

#endif /* BOOST_PROXY_SALT_HASH */