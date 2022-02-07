/**
 * @file CBatch.h
 * @brief Interface definition for inheriting batch classes
 *
 ***********************************************/

#ifndef CBATCH_HPP
#define CBATCH_HPP

#include <iostream>
#include <string>
#include <vector>

#include "utils.h"

/**
 * @class CBatch
 * @brief Interface
 *
 */
class CBatch {
   public:
    virtual ~CBatch();

   protected:
    virtual int get_jobs(const std::vector<std::string> &, std::string &) = 0;
    virtual int get_nodes(const std::vector<std::string> &, std::string &) = 0;
    virtual int get_queues(const std::vector<std::string> &, std::string &) = 0;
    virtual int get_node_states(const std::vector<std::string> &, std::string &) = 0;
    virtual int set_node_state(const std::vector<std::string> &, std::string, std::string) = 0;
};

#endif //CBATCH_HPP