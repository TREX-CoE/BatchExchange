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

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

/**
 * @brief Split string at delimiter
 *
 * @param input Input string reference
 * @param delimiter Delimiter
 * @param ret Reference for output vector
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
 * @param s String to be transformed
 */
void utils::to_lower(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
}

/**
 * @brief Converts string to uppercase
 *
 * @param s String to be transformed
 */
void utils::to_upper(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::toupper(c); });
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

/**
 * @brief Check json output for errors
 *
 * @param o output
 * @return 0 No errors
 * @return 1 Errors found
 */
int utils::check_errors(const std::string &o) {
    rapidjson::Document d;
    if (d.Parse(o.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    if (!d.IsObject())
        return 0;

    std::string errorKey = "";
    if (d.HasMember("errors"))
        errorKey = "errors";
    else if (d.HasMember("error"))
        errorKey = "error";

    if (errorKey.length()) {
        if (d["errors"].IsString()) {
            std::string err = d["errors"].GetString();
            if (err.length()) {
                std::cerr << err << std::endl;
                return 1;
            }
        } else if (d["errors"].IsArray()) {
            auto err = d["errors"].GetArray();
            for (rapidjson::SizeType i = 0; i < err.Size(); i++)
                if (err[i].IsString())
                    std::cerr << err[i].GetString() << std::endl;
        }
    }
    return 0;
}