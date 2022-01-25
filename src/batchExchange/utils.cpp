/**
 * @file utils.cpp
 * @brief Collection of helper functions
 *
 ***********************************************/

#include "utils.h"

#include <fstream>
#include <iostream>
#include <sstream>

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