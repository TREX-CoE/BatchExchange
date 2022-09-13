#include "proxy/globals.h"
#include "proxy/salt_hash.h"
#include "proxy/error.h"

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

std::error_code creds_get(const std::string& user, const std::string& pass, std::set<std::string>& scopes) {
    std::lock_guard<std::mutex> guard(m_creds_);
    auto it = creds_.find(user);
    if (it != creds_.end()) {
        const auto hash = cw::proxy::salt_hash(it->second.salt, pass);
        if (hash == it->second.hash) {
            scopes = it->second.scopes;
            return {};
        }
        return cw::error::error_type::login_password_mismatch;
    }
    return cw::error::error_type::login_user_not_found;
}


std::error_code creds_check(const std::string& user, const std::string& pass, const std::set<std::string>& scopes) {
    std::lock_guard<std::mutex> guard(m_creds_);
    auto it = creds_.find(user);
    if (it != creds_.end()) {
        const auto hash = cw::proxy::salt_hash(it->second.salt, pass);
        if (hash == it->second.hash) {
            if (!scopes.empty()) {
                for (const auto& s : scopes) {
                    if (it->second.scopes.find(s) == it->second.scopes.end()) {
                        // user does not have requested scope
                        return cw::error::error_type::login_scope_missing;
                    }
                }
            }
            return {};
        }
        return cw::error::error_type::login_password_mismatch;
    }
    return cw::error::error_type::login_user_not_found;
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