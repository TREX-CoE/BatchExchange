/**
 * @file utils.cpp
 * @brief Collection of helper functions
 *
 ***********************************************/

#include "utils.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

/**
 * @brief Split string at delimiter
 *
 * @param input Input string
 * @param delimiter Delimiter
 * @param ret Output vector
 */
void utils::str_split(const std::string &input, const std::string delimiter, std::vector<std::string> &ret) {
    const size_t lengthDelimiter = delimiter.length();
    size_t posStartSearch = 0;
    size_t posDelimiter = input.find(delimiter, posStartSearch);

    while (posDelimiter != std::string::npos) {
        ret.push_back(input.substr(posStartSearch, posDelimiter - posStartSearch));
        posStartSearch = posDelimiter + lengthDelimiter;
        posDelimiter = input.find(delimiter, posStartSearch);
    }

    if (posStartSearch < input.length()) {
        ret.push_back(input.substr(posStartSearch));
    }
}

/**
 * @brief Check if string ends with <suffix>
 *
 * @param s Input string
 * @param suffix Suffix
 * @return 0 Suffix not present
 * @return 1 Suffix present
 */
bool utils::ends_with(const std::string &s, const std::string &suffix) {
    return s.size() >= suffix.size() && 0 == s.compare(s.size() - suffix.size(), suffix.size(), suffix);
}

/**
 * @brief Check if string starts with <prefix>
 *
 * @param s Input string
 * @param prefix Prefix
 * @return 0 Prefix not present
 * @return 1 Prefix present
 */
bool utils::starts_with(const std::string &s, const std::string &prefix) {
    return s.size() >= prefix.size() && 0 == s.compare(0, prefix.size(), prefix);
}

/**
 * @brief Check if string matches wildcard-string
 *
 * @param pattern Wildcard pattern
 * @param target Target to be checked
 * @return 0 No match
 * @return 1 Match
 */
bool utils::str_match_wildcard(const std::string &pattern, const std::string &target) {
    if (pattern.find("*") == std::string::npos)
        return pattern == target;

    std::vector<std::string> split;
    utils::str_split(pattern, "*", split);

    // trailing "*" is lost at split -> replace with empty string
    if (utils::ends_with(pattern, "*"))
        split.push_back("");

    std::string regexStr = utils::join_vector_to_string(split, "[\\w\\d_-]*");

    std::regex regex(regexStr);
    return std::regex_match(target, regex);
}

/**
 * @brief Check if string matches any wildcard-string of vector
 *
 * @param pattern Wildcard pattern vector
 * @param target Target to be checked
 * @return 0 No match
 * @return 1 Match
 */
bool utils::str_match_any_wildcard(const std::vector<std::string> &wildcards, const std::string &target) {
    for (auto &v : wildcards) {
        if (utils::str_match_wildcard(v, target))
            return true;
    }
    return false;
}

/**
 * @brief Extract all regex matches from string
 *
 * @param input Input string to be checked
 * @param regex Regex
 * @param ret Vector of matches
 */
void utils::str_extract_regex_occurances(std::string input, const std::regex &regex, std::vector<std::string> &ret) {
    std::smatch res;

    while (std::regex_search(input, res, regex)) {
        ret.push_back(res[0]);
        input = res.suffix();
    }
}

/**
 * @brief Check if string contains only numbers (integer only)
 *
 * @param pattern Wildcard pattern vector
 * @param target Target to be checked
 * @return 0 NaN
 * @return 1 Is number
 */
bool utils::is_number(const std::string &s) {
    // TODO floating point support
    return s.find_first_not_of("0123456789") == std::string::npos;
}

/**
 * @brief Decode brace notation
 *
 * @param input String to be decoded
 * @param ret Vector of decoded strings
 */
void utils::decode_brace(const std::string &input, std::vector<std::string> &ret) {
    std::vector<std::string> split;
    std::regex regex("[a-zA-Z][a-zA-Z0-9\\*]*(\\[[0-9,-]*\\])?[a-zA-Z0-9\\*]*");
    utils::str_extract_regex_occurances(input, regex, split);

    for (auto &v : split) {
        std::cout << v << std::endl;
        size_t braceStart = v.find_first_of("[");
        size_t braceEnd = v.find_first_of("]");
        ssize_t braceContentLen = braceEnd - braceStart - 1;

        if (braceStart != std::string::npos && braceEnd != std::string::npos && braceStart < braceEnd && braceContentLen > 0) {
            std::string prefix = v.substr(0, braceStart);
            std::string braceContent = v.substr(braceStart + 1, braceContentLen);
            std::string suffix = v.substr(braceEnd + 1, v.length() - braceEnd);

            std::vector<std::string> braceList;
            utils::str_split(braceContent, ",", braceList);
            std::vector<std::string> expanded;
            for (auto &b : braceList) {
                if (utils::is_number(b)) {
                    expanded.push_back(b);
                } else {
                    std::vector<std::string> range;
                    utils::str_split(b, "-", range);
                    if (range.size() == 2 && utils::is_number(range[0]) && utils::is_number(range[1])) {
                        int start = std::stoi(range[0]);
                        int stop = std::stoi(range[1]);
                        if (stop < start) {
                            int tmp = start;
                            start = stop;
                            stop = tmp;
                        }
                        for (int i = start; i <= stop; i++) {
                            expanded.push_back(std::to_string(i));
                        }
                    }
                }
                for (auto &e : expanded) {
                    ret.push_back(prefix + e + suffix);
                }
            }

        } else {
            ret.push_back(v);
        }
    }
    return;
}

/**
 * @brief Reads login data from loginFile
 * TODO rework
 *
 */
void utils::read_login_data(const std::string &path, utils::loginData &megware, utils::loginData &xcat, utils::loginData &slurm, bool ignoreHeader) {
    std::string fileContent;
    utils::read_file_to_string(path, fileContent);

    std::string line;
    std::vector<std::string> tmpLoginData;

    if (ignoreHeader) {
        utils::erase_lines_from_start(fileContent, 1);
    }

    std::istringstream iss(fileContent);

    std::getline(iss, line);
    utils::str_split(line, ",", tmpLoginData);
    megware.username = tmpLoginData[1];
    megware.password = tmpLoginData[2];
    megware.host = tmpLoginData[3];
    megware.port = tmpLoginData[4];

    tmpLoginData.clear();

    std::getline(iss, line);
    utils::str_split(line, ",", tmpLoginData);
    xcat.username = tmpLoginData[1];
    xcat.password = tmpLoginData[2];
    xcat.host = tmpLoginData[3];
    xcat.port = tmpLoginData[4];

    tmpLoginData.clear();

    std::getline(iss, line);
    utils::str_split(line, ",", tmpLoginData);
    slurm.username = tmpLoginData[1];
    slurm.password = tmpLoginData[2];
    slurm.host = tmpLoginData[3];
    slurm.port = tmpLoginData[4];
}

/**
 * @brief Read file and save to string reference
 *
 * @param path Path + filename of file
 * @param output Reference to write file to
 * @return 0 Success
 * @return 1 Error opening file
 */
int utils::read_file_to_string(std::string path, std::string &output) {
    std::ifstream fileStream(path);
    if (!fileStream.is_open() || !fileStream.good()) {
        std::cerr << "Error reading file (" << path << ")." << std::endl;
        return 1;
    }
    std::stringstream buffer;
    buffer << fileStream.rdbuf();
    fileStream.close();
    output = buffer.str();
    return 0;
}

/**
 * @brief Write data to file
 *
 * @param path Path + filename of file
 * @param data Data to be written to file
 * @return 0 Success
 * @return 1 Error writing to file
 */
int utils::write_to_file(std::string path, const std::string &data) {
    std::ofstream ofs(path, std::ofstream::out | std::ofstream::app);
    if (!ofs) {
        std::cerr << "Error writing to file (" << path << ")." << std::endl;
        return 1;
    }
    ofs << data;
    ofs.close();
    return 0;
}

/**
 * @brief Remove the first <lineCount> lines from referenced string
 *
 * @param data String to be modified
 * @param lineCount Lines to be erased
 */
void utils::erase_lines_from_start(std::string &data, int lineCount) {
    for (int i = 0; i < lineCount; i++)
        data.erase(0, data.find("\n") + 1);
}

/**
 * @brief Converts string to lowercase
 *
 * @param s String reference to be transformed
 */
void utils::to_lower(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
}

/**
 * @brief Join all elements of a string-vector to a single string with delimiter
 *
 * @param vec Vector to be joined
 * @param delim Delimiter
 * @return joined string
 */
std::string utils::join_vector_to_string(const std::vector<std::string> &vec, const std::string delim) {
    std::string ret;
    for (const auto &s : vec) {
        if (!ret.empty())
            ret += delim;
        ret += s;
    }
    return ret;
}