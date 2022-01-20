#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

struct loginData {
    std::string username;
    std::string password;
    std::string host;
    std::string port;
};

void str_split(const std::string &input, const std::string delimiter, std::vector<std::string> &ret);
void read_login_data(const std::string &path, loginData &megware, loginData &xcat, loginData &slurm, bool ignoreHeader = true);

#endif //UTILS_H