#ifndef BOOST_PROXY_RANDOM_HEX
#define BOOST_PROXY_RANDOM_HEX

#include <random>
#include <ctime>

namespace cw {
namespace helper {



std::string random_hex(unsigned int length) {
    const char* hex_chars = "0123456789abcdef";
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> rnd_hex(0,15);
    std::string s;
    for (unsigned int i=0;i<length;i++) s.push_back(hex_chars[rnd_hex(rng)]);
    return s;
}

}
}

#endif /* BOOST_PROXY_RANDOM_HEX */
