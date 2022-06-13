#ifndef BOOST_PROXY_URI
#define BOOST_PROXY_URI

#include <string>
#include <vector>
#include <map>

namespace cw {
namespace helper {
namespace uri {

struct Uri {
    std::string scheme;
    std::string domain;
    std::vector<std::string> path;
    std::map<std::string, std::string> query;
    std::string fragment;
    bool has_value() const;
    static bool parse(Uri& uri, const std::string& input);
};

}
}
}

#endif /* BOOST_PROXY_URI */