/**
 * @file CBatch.hpp
 * @author Nico Tippmann
 * @brief Header for CBatch.cpp
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
    virtual std::string getJobs(int) = 0;
    virtual std::string getNodes(std::string = "") = 0;
    virtual std::string getQueues(std::string = "") = 0;
    virtual std::string getNodeStatus(std::string) = 0;
    virtual int setNodeStatus(std::vector<std::string>, std::string) = 0;
};

#endif /* CBATCH_HPP */