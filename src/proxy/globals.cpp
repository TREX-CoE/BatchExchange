#include "proxy/globals.h"
#include "proxy/salt_hash.h"

#include <mutex>

namespace {

cw::helper::credentials::dict creds_;
std::string cred_file_;

std::mutex m_creds_;


}

namespace cw {
namespace globals {

void init(const cw::helper::credentials::dict& creds, const std::string& cred_file) {
    creds_ = creds;
    cred_file_ = cred_file;
}

cw::helper::credentials::dict creds() {
    std::lock_guard<std::mutex> guard(m_creds_);
    return creds_;
}

bool creds_check(string_view header, const std::set<std::string>& scopes) {
    std::string user, pass;
    if (cw::http::parse_auth_header(header, user, pass)) {
        std::lock_guard<std::mutex> guard(m_creds_);
        auto it = creds_.find(user);
        if (it != creds_.end()) {
            const auto hash = cw::proxy::salt_hash(it->second.salt, pass);
            if (hash == it->second.hash) {
                if (!scopes.empty()) {
                    for (const auto& s : scopes) {
                        if (it->second.scopes.find(s) == it->second.scopes.end()) {
                            // user does not have requested scope
                            return false;
                        }
                    }
                }
                return true;
            }
        }
    }
    return false;
}

void creds(cw::helper::credentials::dict _creds) {
    std::lock_guard<std::mutex> guard(m_creds_);
    creds_ = _creds;
}

const std::string& cred_file() {
    return cred_file_;
}

}
}