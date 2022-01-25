/**
 * @file CBatch.h
 * @author Nico Tippmann
 * @brief Interface definition for inheriting batch classes
 *
 ***********************************************/

#ifndef CBATCH_HPP
#define CBATCH_HPP

#include <iostream>
#include <string>
#include <vector>

/**
 * @class CBatch
 * @brief Interface
 *
 */
class CBatch {
   public:
    virtual ~CBatch();

   protected:
    virtual std::string get_jobs(int) = 0;
    virtual std::string get_nodes(std::string = "") = 0;
    virtual std::string get_queues(std::string = "") = 0;
    virtual std::string get_node_state(std::string) = 0;
    virtual int set_node_state(std::vector<std::string>, std::string) = 0;
};

#endif /* CBATCH_HPP */