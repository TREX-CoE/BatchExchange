#include "proxy/cmd_user.h"

#include "proxy/set_echo.h"
#include "proxy/credentials.h"

#include <iostream>

namespace {

std::string prompt(const std::string& prefix) {
    if (!prefix.empty()) {
        std::cout << prefix;
        std::cout.flush();
    }
    cw::helper::set_echo(false);
    std::string input;
    std::getline(std::cin, input);
    cw::helper::set_echo(true);
    return input;
}

}

namespace cw {
namespace proxy {
namespace cmd {
namespace user {

int set(const std::string& cred_file, const std::string& username, const std::vector<std::string>& scopes, const std::string& promptstr) {
    cw::helper::credentials::dict creds;
    if (!cw::helper::credentials::read_file(cred_file, creds)) return 1;
    
    std::set<std::string> scopes_set(scopes.begin(), scopes.end());
    cw::helper::credentials::set_user(creds, username, scopes_set, prompt(promptstr));

    if (!cw::helper::credentials::write_file(cred_file, creds)) return 1;
    return 0;
}

int remove(const std::string& cred_file, const std::string& username) {
    cw::helper::credentials::dict creds;
    if (!cw::helper::credentials::read_file(cred_file, creds)) return 1;

    auto it = creds.find(username);
    if (it == creds.end()) {
        std::cout << "Username '" << username << "' not found" << std::endl;
        return 1;
    }
    creds.erase(it);
    
    if (!cw::helper::credentials::write_file(cred_file, creds)) return 1;
    return 0;
}

}
}
}
}
