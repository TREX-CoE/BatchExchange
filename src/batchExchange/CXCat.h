#ifndef XCAT_H
#define XCAT_H

#include <string>

#include "restClient.h"
#include "sessionTokenTypes.h"

class CXCat {
   private:
    RestClient *session;

   public:
    CXCat(std::string host, std::string port, std::string username, std::string password, bool sslVerify);

    ~CXCat();

    void set_user_credentials(std::string username, std::string password);
    void set_host_config(std::string host, std::string port);
    void ssl_verify(bool sslVerify);

    int  login();
    void logout();

    std::string get_os_image(std::string node);
    void set_os_image(std::string node, std::string osImage);
    void set_os_image_n_reboot(std::string node, std::string osImage);
    void reboot_node(std::string node);
};

#endif  // XCAT_H