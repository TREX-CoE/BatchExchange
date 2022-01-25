/**
 * @file CBatchSlurm.h
 * @brief Header for CBatchSlurm.cpp
 *
 ***********************************************/

#ifndef CBATCHSLURM_HPP
#define CBATCHSLURM_HPP

#include "CBatch.h"
#include "rapidjson/document.h"
#include "restClient.h"
#include "sessionTokenTypes.h"

/**
 * @class CBatchSlurm
 * @brief Slurm Class
 *
 */
class CBatchSlurm : public CBatch {
   public:
    CBatchSlurm(std::string, std::string, std::string, std::string, bool);
    virtual ~CBatchSlurm();
    int login();
    int logout();
    int get_jobs(int);
    int get_nodes(std::string, std::string &, bool);
    int get_queues(std::string);
    int get_node_state(std::string);
    int set_node_state(std::vector<std::string>, std::string);

   private:
    int get_api_version();
    void set_user_credentials(std::string username, std::string password);
    void set_host_config(std::string host, std::string port);
    void ssl_verify(bool sslVerify);

	RestClient *openapiSession;
    RestClient *session;
    std::string apiVersion = "";
};

#endif /* CBATCHSLURM_HPP */