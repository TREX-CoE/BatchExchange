#include "proxy/uri.h"
#include "shared/splitString.h"

#include <regex>

namespace {

const std::regex r_uri{R"(^(([^:\/?#]+):)?(//([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)", std::regex::extended};

const std::string queryDel = "&";
const std::string pathDel = "/";
}

namespace cw {
namespace helper {
namespace uri {

bool Uri::has_value() const { return !scheme.empty(); }

bool Uri::parse(Uri& uri, const std::string& input) {
    std::smatch res;

    if (std::regex_match(input, res, r_uri)) {
        uri.scheme = res[2];
        uri.domain = res[4];
        std::string path = res[5];
        if (path.rfind("/", 0) == 0) path.erase(0, 1);
        cw::helper::splitString(path, pathDel, [&uri, &path](size_t start, size_t end){
            uri.path.push_back(path.substr(start, end));
            return true;
        });

        std::string query = res[7];
        cw::helper::splitString(query, queryDel, [&uri, &query](size_t start, size_t end){
            std::string s = query.substr(start, end);
            size_t delpos = s.find("=");
            if (delpos == std::string::npos) {
                uri.query[std::move(s)] = "";
            } else {
                uri.query[s.substr(0, delpos)] = s.substr(delpos+1);
            }
            return true;
        });

        uri.fragment = res[9];
        return true;
    }
    return false;
}

Uri& Uri::remove_prefix(size_t len) {
    path.erase(path.begin(), path.begin() + len);
    return *this;
}

}
}
}