/**
 * @file CBatchSlurm.h
 * @brief Header for CBatchSlurm.cpp
 *
 ***********************************************/

#ifndef CBATCHSLURM_HPP
#define CBATCHSLURM_HPP

#include "CBatch.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "../../external/restclient/src/restClient.h"
#include "../../external/restclient/src/sessionTokenTypes.h"

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
    int get_jobs(const std::vector<std::string> &, std::string &);
    int get_nodes(const std::vector<std::string> &, std::string &);
    int get_queues(const std::vector<std::string> &, std::string &);
    int get_node_states(const std::vector<std::string> &, std::string &);
    int set_node_state(const std::vector<std::string> &, std::string, std::string);
    int drain_nodes(std::vector<std::string> &, const std::string &);
    int drained(std::vector<std::string> &, unsigned int &);

   private:
    int get_api_version();
    void set_user_credentials(std::string, std::string);
    void set_host_config(std::string, std::string);
    void ssl_verify(bool);
    int filter_output(const std::vector<std::string> &, const std::string &, std::string &, std::string, std::string);

    RestClient *openapiSession;
    RestClient *session;
    std::string apiVersion = "";
};

#endif //CBATCHSLURM_HPP