#include "proxy/credentials.h"
#include "proxy/salt_hash.h"

#include <ostream>
#include <istream>

static string_view delimiter = ":";

namespace credentials {

void read(dict& creds, std::istream& in) {
    std::string line;
    while(std::getline(in, line)) {
        if (line.empty()) continue;
        size_t idx = line.find(delimiter.data());
        if (idx != std::string::npos) {
            std::string user = line.substr(0, idx);
            line.erase(0, idx+delimiter.size());
            idx = line.find(delimiter.data());
            if (idx != std::string::npos) {
                creds[user] = std::make_pair(line.substr(0, idx), line.substr(idx+delimiter.size()));
            }
        }
    }
}

void write(const dict& creds, std::ostream &out) {
    for (const auto& p : creds) {
        out << p.first << delimiter.data() << p.second.first << delimiter.data() << p.second.second << std::endl;
    }
}

std::string check_header(const dict& creds, string_view header) {
    std::string user, pass;
    if (cw::http::parse_auth_header(header, user, pass)) {
        auto it = creds.find(user);
        if (it != creds.end()) {
            const auto hash = cw::proxy::salt_hash(it->second.first, pass);
            if (hash == it->second.second) return user;
        }
    }
    return "";
}

}