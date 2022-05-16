#ifndef BOOST_SHARED_SPLIT_STRING
#define BOOST_SHARED_SPLIT_STRING

#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>

namespace cw {
namespace helper {

template <typename S1, typename S2, typename F>
static inline void splitString(S1 str, S2 delimiter, F cb) {
	size_t delim_len = delimiter.length();
    size_t start = 0;
	size_t end;

    while ((end = str.find(delimiter, start)) != std::string::npos) {
        if (!cb(start, end-start)) return;
        start = end + delim_len;
    }
	cb(start, end);
} 

}	
}

#endif /* BOOST_SHARED_SPLIT_STRING */