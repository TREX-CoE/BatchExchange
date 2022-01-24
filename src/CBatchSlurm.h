/**
 * @file CBatchSlurm.h
 * @author Nico Tippmann
 * @brief Header for CBatchSlurm.cpp
 *
 ***********************************************/

#ifndef CBATCHSLURM_HPP
#define CBATCHSLURM_HPP

#include "CBatch.h"
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
    std::string get_jobs(int);
    std::string get_nodes(std::string = "");
    std::string get_queues(std::string = "");
    std::string get_node_state(std::string);
    int set_node_state(std::vector<std::string>, std::string);

   private:
    int login();
    void get_api_version();
    void set_user_credentials(std::string username, std::string password);
    void set_host_config(std::string host, std::string port);
    void ssl_verify(bool sslVerify);

    RestClient *slurmSession;
    std::string apiVersion;
};

#endif /* CBATCHSLURM_HPP */