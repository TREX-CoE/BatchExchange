#ifndef CURLHELPER_H
#define CURLHELPER_H

#include <string>

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, nmemb);
 
    size_t realsize = size * nmemb;
    return realsize;
}

#endif //CURLHELPER_H