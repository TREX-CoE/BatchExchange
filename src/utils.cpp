#include <iostream>
#include <fstream>
#include <sstream>


#include "utils.h"

void str_split(const std::string &input, const std::string delimiter, std::vector<std::string> &ret) {
    const size_t lengthDelimiter = delimiter.length();
    size_t posStartSearch = 0;
    size_t posDelimiter = input.find(delimiter, posStartSearch);


    while(posDelimiter != std::string::npos) {
        ret.push_back(input.substr(posStartSearch, posDelimiter-posStartSearch));
        posStartSearch = posDelimiter + lengthDelimiter;
        posDelimiter = input.find(delimiter, posStartSearch);
    }

    if (posStartSearch < input.length()) {
        ret.push_back(input.substr(posStartSearch));
    }
}


void read_login_data(const std::string &path, loginData &megware, loginData &xcat, bool ignoreHeader) {
    std::ifstream infile(path);
    std::string line;
    std::vector<std::string> tmpLoginData;
    
    if (ignoreHeader) {
        std::getline(infile, line);
    }

    std::getline(infile, line);
    str_split(line, ",", tmpLoginData);
    megware.username = tmpLoginData[1];
    megware.password = tmpLoginData[2];
    megware.host     = tmpLoginData[3];
    megware.port     = tmpLoginData[4];

    tmpLoginData.clear();

    std::getline(infile, line);
    str_split(line, ",", tmpLoginData);
    xcat.username = tmpLoginData[1];
    xcat.password = tmpLoginData[2];
    xcat.host     = tmpLoginData[3];
    xcat.port     = tmpLoginData[4];
}