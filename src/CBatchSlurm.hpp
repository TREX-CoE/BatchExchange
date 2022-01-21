/**
 * @file CBatchSlurm.hpp
 * @author Nico Tippmann
 * @brief Header for CBatchSlurm.cpp
 *
 ***********************************************/

#ifndef CBATCHSLURM_HPP
#define CBATCHSLURM_HPP

#include "CBatch.hpp"
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
    std::string getJobs(int);
    std::string getNodes(std::string = "");
    std::string getQueues(std::string = "");
    std::string getNodeStatus(std::string);
    int setNodeStatus(std::vector<std::string>, std::string);
    int login();

   private:
    void getApiVersion();
    void set_user_credentials(std::string username, std::string password);
    void set_host_config(std::string host, std::string port);
    void ssl_verify(bool sslVerify);

    RestClient *slurmSession;
    std::string apiVersion;
};

#endif /* CBATCHSLURM_HPP */