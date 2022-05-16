#ifndef BOOST_PROXY_SHARED_SALT_HASH
#define BOOST_PROXY_SHARED_SALT_HASH

#include "shared/sha512.h"
#include "shared/string_view.h"
#include "shared/obfuscator.h"

#include <string>

namespace cw {
namespace helper {

template <unsigned int N, unsigned char Key, typename T>
std::string salt_hash(const cw::helper::obfuscator<N, Key, T>& pepper, string_view salt, string_view input) {
    char buf[N];
    pepper.deobfuscate(buf);

    // merge pepper, salt and input together
    std::string h;
    h.reserve(N+salt.size()+input.size());
    const auto max = std::max<size_t>({N, salt.size(), input.size()});
    for (size_t i=0; i<max; ++i) {
        if (i < N) h.push_back(buf[i]);
        if (i < salt.size()) h.push_back(salt[i]);
        if (i < input.size()) h.push_back(input[i]);
    }
    return cw::helper::sha512_hash(h);
}

}
}

#endif /* BOOST_PROXY_SHARED_SALT_HASH */