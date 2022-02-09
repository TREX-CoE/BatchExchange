/**
 * @file CXCat.h
 * @brief Header for CXCat
 *
 *
 ***********************************************/

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
    int get_os_images(const std::vector<std::string> &, std::string &);
    int get_os_image_names(std::vector<std::string> &);
    int get_bootstate(const std::vector<std::string> &, std::string &);
    int get_nodes(std::string &);
    int set_os_image(const std::vector<std::string> &, std::string);
    int reboot_nodes(const std::vector<std::string> &);
    int set_postscript(const std::vector<std::string> &, std::string);
    int set_group_attributes(std::string, const std::string &);
    int set_node_attributes(const std::vector<std::string> &, const std::string &);
    int get_group_members(std::string group, std::vector<std::string> &output);
    int get_group_names(std::vector<std::string> &);
    int get_group(std::string, std::string &);
};

#endif  // XCAT_H