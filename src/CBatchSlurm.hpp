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
    CBatchSlurm();
    ~CBatchSlurm();
    std::string getJobs(int);
    std::string getNodes(std::string);
    std::string getQueues(std::string);
    std::string getNodeStatus(std::string);
    int setNodeStatus(std::vector<std::string>, std::string);

    RestClient *RC;
};

#endif /* CBATCHSLURM_HPP */