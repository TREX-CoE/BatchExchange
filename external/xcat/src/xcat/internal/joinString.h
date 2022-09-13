#include <string>

namespace xcat {
namespace internal {

template <typename Iterator>
static inline std::string joinString(Iterator begin, Iterator end, const std::string& del) {
    if (begin == end) return "";
    std::string out = *begin;
    ++begin;
    while (begin != end) {
        out += del + *begin;
        ++begin;
    }
    return out;
}

}	
}
