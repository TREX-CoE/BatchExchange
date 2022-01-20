/**
 * @file CBatch.hpp
 * @author Nico Tippmann
 * @brief Header for CBatch.cpp
 *
 ***********************************************/

#ifndef CBATCH_HPP
#define CBATCH_HPP

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
    virtual std::string getJobs(int);
    virtual std::string getNodes(std::string);
    virtual std::string getQueues(std::string);
    virtual std::string getNodeStatus(std::string);
    virtual int setNodeStatus(std::vector<std::string>, std::string);
};

#endif /* CBATCH_HPP */