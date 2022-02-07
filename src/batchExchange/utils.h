/**
 * @file utils.h
 * @brief Header for utils.cpp
 *
 ***********************************************/

#ifndef UTILS_H
#define UTILS_H

#include <algorithm>
#include <regex>
#include <string>
#include <vector>

#define INVALID_JSON_ERROR_MSG "Error - Response is not valid JSON"

namespace utils {
struct loginData {
    std::string username;
    std::string password;
    std::string host;
    std::string port;
};

/* According to the Slurm documentation only a subset of the below listed states can actually be set via scontrol.
 * However, the documentation differs substantially from the actual behaviour of scontrol.
 * Therefore all possible node states are allowed for now.
 */
const std::vector<std::string> slurmNodeStates = {
    "alloc",
    "allocated",
    "cancel_reboot",
    "cloud",
    "comp",
    "completing",
    "down",
    "down-drain",
    "drain",
    "drained",
    "draining",
    "fail",
    "futr",
    "future",
    "idle",
    "maint",
    "mix",
    "mixed",
    "no_respond",
    "noresp",
    "npc",
    "perfctrs",
    "planned",
    "power_down",
    "power_up",
    "powered_down",
    "powering_down",
    "powering_up",
    "reboot_issued",
    "reboot_requested",
    "reserved",
    "resume",
    "resv",
    "undrain",
    "unk",
    "unknown",
};

void str_split(const std::string &input, const std::string delimiter, std::vector<std::string> &ret);
void read_login_data(const std::string &path, utils::loginData &megware, utils::loginData &xcat, utils::loginData &slurm, bool ignoreHeader = true);
int read_file_to_string(std::string, std::string &);
int write_to_file(std::string, const std::string &);
void erase_lines_from_start(std::string &, int);
void to_lower(std::string &);
void to_upper(std::string &);
std::string join_vector_to_string(const std::vector<std::string> &, const std::string);
int check_errors(const std::string &);
void str_extract_regex_occurances(std::string, const std::regex &, std::vector<std::string> &);
bool is_number(const std::string &);
void decode_brace(const std::string &, std::vector<std::string> &);
bool str_match_wildcard(const std::string &, const std::string &);
bool ends_with(const std::string &, const std::string &);
bool starts_with(const std::string &, const std::string &);
bool str_match_any_wildcard(const std::vector<std::string>&, const std::string &);

/**
 * @brief Template function to check whether a vector contains the specified element
 *
 * @param v Vector
 * @param e Element
 * @return 0 Element not in vector
 * @return 1 Element in vector
 */
template <typename T>
bool vector_contains(const std::vector<T> &v, const T &e) {
    return (std::find(v.begin(), v.end(), e) != v.end());
}
}  // namespace utils
#endif  //UTILS_H