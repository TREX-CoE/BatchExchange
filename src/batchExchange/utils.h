/**
 * @file utils.h
 * @brief Header for utils.cpp
 *
 ***********************************************/

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

namespace utils {
struct loginData {
    std::string username;
    std::string password;
    std::string host;
    std::string port;
};

const std::vector<std::string> slurmNodeStates = {
    "down",
    "resume",
    "drain",
    "undrain",
    "fail",
    "cancel_reboot",
    "future",
    "noresp",
    "power_down",
    "power_up"};

void str_split(const std::string &input, const std::string delimiter, std::vector<std::string> &ret);
void read_login_data(const std::string &path, utils::loginData &megware, utils::loginData &xcat, utils::loginData &slurm, bool ignoreHeader = true);
int read_file_to_string(std::string, std::string &);
int write_to_file(std::string, const std::string &);
void erase_lines_from_start(std::string &, int);
void to_lower(std::string &);
std::string joinVector(const std::vector<std::string> &, const std::string);
}  // namespace utils
#endif  // UTILS_H