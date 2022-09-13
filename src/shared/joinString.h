#ifndef BOOST_SHARED_JOIN_STRING
#define BOOST_SHARED_JOIN_STRING

#include <string>

namespace cw {
namespace helper {

template <typename Iterator, typename S>
static inline std::string joinString(Iterator begin, Iterator end, S del) {
    if (begin == end) return "";
    std::string out = *begin;
    ++begin;
    while (begin != end) {
        out += std::string(del) + *begin;
        ++begin;
    }
    return out;
}

}
}

#endif /* BOOST_SHARED_JOIN_STRING */