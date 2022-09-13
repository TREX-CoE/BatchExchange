#ifndef BOOST_PROXY_STREAM_CAST
#define BOOST_PROXY_STREAM_CAST

#include <sstream>

namespace cw {
namespace helper {

template<typename T>
static inline bool stream_cast(const std::string& s, T& out)
{
    std::istringstream ss(s);
    if ((ss >> out).fail() || !(ss >> std::ws).eof()) return false;
    return true;
}

}
}

#endif /* BOOST_PROXY_STREAM_CAST */