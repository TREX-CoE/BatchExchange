#include "proxy/credentials.h"
#include "proxy/salt_hash.h"

#include "shared/splitString.h"
#include "shared/joinString.h"
#include "shared/randomHex.h"

#include <sstream>
#include <iostream>
#include <fstream>

static const std::string delimiter = ":";
static const std::string scope_delimiter = ",";

namespace cw {
namespace helper {
namespace credentials {

void set_password(user_data& user, boost::string_view password) {
    user.salt = cw::helper::random_hex(16);
    user.hash = cw::proxy::salt_hash(user.salt, password);
}

void read(dict& creds, const std::string& s) {
    std::stringstream in(s);
    std::string line;
    while(std::getline(in, line)) {
        if (line.empty()) continue;
        std::string user;
        user_data data;
        unsigned int i = 0;
        cw::helper::splitString(line, delimiter, [&](const auto idx1, const auto idx2){
            switch (i) {
                case 0: user=line.substr(idx1, idx2); break;
                case 1: {
                    std::string l2 = line.substr(idx1, idx2);
                    cw::helper::splitString(l2, scope_delimiter, [&](const auto i1, const auto i2){
                        data.scopes.insert(l2.substr(i1, i2));
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

void write(const dict& creds, std::string& out) {
    for (const auto& p : creds) {
        out += p.first + delimiter + cw::helper::joinString(p.second.scopes.begin(), p.second.scopes.end(), scope_delimiter) + delimiter.data() + p.second.salt + delimiter + p.second.hash + "\n";
    }
}

bool read_file(const std::string& cred_file, cw::helper::credentials::dict& creds) {
    std::ifstream creds_fs(cred_file);
    if (!creds_fs.good()) {
        std::cout << "Could not open '" << cred_file << "' for reading" << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << creds_fs.rdbuf();

    read(creds, buffer.str());
    return true;
}

bool write_file(const std::string& cred_file, const cw::helper::credentials::dict& creds) {
    std::ofstream creds_fso(cred_file);
    if (!creds_fso.good()) {
        std::cout << "Could not open '" << cred_file << "' for writing" << std::endl;
        return false;
    }

    std::string out;
    write(creds, out);
    creds_fso << out;
    return true;
}

void set_user(credentials::dict& creds, boost::string_view user, std::set<std::string> scopes, boost::string_view password) {
    if (scopes.count("")) {
        // remove marker for not specified and simply add empty set
        scopes = {};
    }
    user_data data;
    set_password(data, password);
    data.scopes = scopes;
    creds[std::string(user)] = std::move(data);
}


dict::const_iterator check_header(const dict& creds, boost::string_view header) {
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
}