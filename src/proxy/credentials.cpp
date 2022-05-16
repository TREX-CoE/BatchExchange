#include "proxy/credentials.h"
#include "proxy/salt_hash.h"

#include "shared/splitString.h"
#include "shared/joinString.h"
#include "shared/randomHex.h"

#include <ostream>
#include <istream>

static string_view delimiter = ":";
static string_view scope_delimiter = ",";

namespace {

std::string generate_salt() {
    return cw::helper::random_hex(16);
}

}

namespace cw {
namespace credentials {

void read(dict& creds, std::istream& in) {
    std::string line;
    while(std::getline(in, line)) {
        if (line.empty()) continue;
        auto l = string_view(line);
        std::string user;
        user_data data;
        unsigned int i = 0;
        cw::helper::splitString(l, delimiter, [&](const auto idx1, const auto idx2){
            switch (i) {
                case 0: user=line.substr(idx1, idx2); break;
                case 1: {
                    cw::helper::splitString(l.substr(idx1, idx2), scope_delimiter, [&](const auto i1, const auto i2){
                        data.scopes.insert(line.substr(i1, i2));
                        return true;
                    });
                    break;
                }
                case 2: data.salt=line.substr(idx1, idx2); break;
                case 3: data.hash=line.substr(idx1, idx2); break;
                default: return false;
            }
            ++i;
            return true;
        });
        if (i == 4) {
            creds[user] = std::move(data);
        } 
    }
}

void write(const dict& creds, std::ostream &out) {
    for (const auto& p : creds) {
        out << p.first << delimiter.data() << cw::helper::joinString(p.second.scopes.begin(), p.second.scopes.end(), scope_delimiter) << delimiter.data() << p.second.salt << delimiter.data() << p.second.hash << std::endl;
    }
}

void set_user(credentials::dict& creds, string_view user, std::set<std::string> scopes, string_view password) {
    std::string salt = generate_salt();
    std::string hash = cw::proxy::salt_hash(salt, password);
    creds[std::string(user)] = credentials::user_data{scopes, salt, hash};
}


dict::const_iterator check_header(const dict& creds, string_view header) {
    std::string user, pass;
    if (cw::http::parse_auth_header(header, user, pass)) {
        auto it = creds.find(user);
        if (it != creds.end()) {
            const auto hash = cw::proxy::salt_hash(it->second.salt, pass);
            if (hash == it->second.hash) return it;
        }
    }
    return creds.end();
}

}
}