#ifndef XCAT_H
#define XCAT_H

#include <string>

#include "restClient.h"
#include "sessionTokenTypes.h"

class CXCat {
   private:
    RestClient *session;
    void set_user_credentials(std::string, std::string);
    void set_host_config(std::string, std::string);
    void ssl_verify(bool);

   public:
    CXCat(std::string, std::string, std::string, std::string, bool);

    ~CXCat();

    int login();
    int logout();
    int get_os_images(std::vector<std::string> &, std::string &);
    int get_bootstate(std::vector<std::string> &, std::string &);
    int get_nodes(std::string &);
    int set_os_image(std::vector<std::string> &, std::string);
    int reboot_nodes(std::vector<std::string> &);
    int get_os_image_names(std::vector<std::string> &);
};

#endif //XCAT_H