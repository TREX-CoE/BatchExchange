#ifndef BOOST_PROXY_BATCHSYSTEM_JSON
#define BOOST_PROXY_BATCHSYSTEM_JSON

#include "batchsystem/batchsystem.h"
#include "proxy/validation.h"

#include <boost/optional.hpp>

namespace {

using namespace cw::batch;

bool getForce(const rapidjson::Document& document) {
        return document.HasMember("force") && document["force"].IsBool() && document["force"].GetBool();
}

std::string getJob(const rapidjson::Document& document) {
        if (!document.HasMember("job")) throw cw::helper::ValidationError("No job given");
        auto& job = document["job"];
        if (!job.IsString()) throw cw::helper::ValidationError("Job is not a string");
        return std::string(job.GetString());
}

std::string getNode(const rapidjson::Document& document) {
        if (!document.HasMember("node")) throw cw::helper::ValidationError("No node given");
        auto& node = document["node"];
        if (!node.IsString()) throw cw::helper::ValidationError("Node is not a string");
        return std::string(node.GetString());
}

std::string getQueue(const rapidjson::Document& document) {
        if (!document.HasMember("queue")) throw cw::helper::ValidationError("No queue given");
        auto& queue = document["queue"];
        if (!queue.IsString()) throw cw::helper::ValidationError("Queue is not a string");
        return std::string(queue.GetString());
}

std::string getState(const rapidjson::Document& document) {
        if (!document.HasMember("state")) throw cw::helper::ValidationError("No state given");
        auto& queue = document["state"];
        if (!queue.IsString()) throw cw::helper::ValidationError("State is not a string");
        return std::string(queue.GetString());
}

QueueState convertQueue(const std::string& str) {
        if (str == "open") {
                return QueueState::Open;
        } else if (str == "closed") {
                return QueueState::Closed;
        } else if (str == "inactive") {
                return QueueState::Inactive;
        } else if (str == "draining") {
                return QueueState::Draining;
        } else {
                throw cw::helper::ValidationError("Invalid queue state");
        }
}


NodeChangeState convertNodeChange(const std::string& str) {
        if (str == "resume") {
                return NodeChangeState::Resume;
        } else if (str == "drain") {
                return NodeChangeState::Drain;
        } else if (str == "undrain") {
                return NodeChangeState::Undrain;
        } else {
                throw cw::helper::ValidationError("Invalid node state");
        }
}

}


namespace cw_proxy_batch {

using namespace cw::batch;

boost::optional<JobOptions> runJob(rapidjson::Document& document, std::string& err) {
    JobOptions opts;
    if (!document.HasMember("path")) {
        err = "path is not given";
        return {};
    } else {
        auto& path = document["path"];
        if (!path.IsString()) {
                err = "path is not a string";
                return {};
        }
        opts.path = std::string(path.GetString());
    }

    if (document.HasMember("nodes")) {
            auto& nodes = document["nodes"];
            if (!nodes.IsInt()) {
                err = "nodes is not an int";
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                err = "nodes has to be atleast 1";
                return {};
            }
            opts.numberNodes = static_cast<uint32_t>(nnodes);
    }
    if (document.HasMember("nodesMax")) {
            auto& nodes = document["nodesMax"];
            if (!nodes.IsInt()) {
                err = "nodesMax is not an int";
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                err = "nodesMax has to be atleast 1";
                return {};
            }
            opts.numberNodesMax = static_cast<uint32_t>(nnodes);
    }
    if (document.HasMember("gpus")) {
            auto& nodes = document["gpus"];
            if (!nodes.IsInt()) {
                err = "gpus is not an int";
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                err = "gpus has to be atleast 1";
                return {};
            }
            opts.numberNodesMax = static_cast<uint32_t>(nnodes);
    }
    return {opts};
}


auto deleteJobById(BatchInterface& batch, rapidjson::Document& document) {
    return batch.deleteJobById(getJob(document), getForce(document)); 
}

auto deleteJobByUser(BatchInterface& batch, rapidjson::Document& document) {
    if (!document.HasMember("user")) throw cw::helper::ValidationError("No user given");
    auto& user = document["user"];
    if (!user.IsString()) throw cw::helper::ValidationError("User is not a string");
    return batch.deleteJobByUser(std::string(user.GetString()), getForce(document));
}

auto changeNodeState(BatchInterface& batch, rapidjson::Document& document) {
    std::string reasonText;
    if (document.HasMember("reason")) {
            auto& reason = document["reason"];
            if (!reason.IsString()) throw cw::helper::ValidationError("Reason is not a string");
            reasonText = reason.GetString();
    }
    bool appendReason = document.HasMember("append") && document["append"].IsBool() && document["append"].GetBool();

    return batch.changeNodeState(getNode(document), convertNodeChange(getState(document)), getForce(document), reasonText, appendReason);
}

auto setQueueState(BatchInterface& batch, rapidjson::Document& document) {
    return batch.setQueueState(getQueue(document), convertQueue(getState(document)), getForce(document));
}

auto setNodeComment(BatchInterface& batch, rapidjson::Document& document) {
    if (!document.HasMember("comment")) throw cw::helper::ValidationError("No comment given");
    auto& comment = document["comment"];
    if (!comment.IsString()) throw cw::helper::ValidationError("Comment is not a string");
    bool appendComment = document.HasMember("append") && document["append"].IsBool() && document["append"].GetBool();

    return batch.setNodeComment(getNode(document), getForce(document), std::string(comment.GetString()), appendComment);
}

auto holdJob(BatchInterface& batch, rapidjson::Document& document) {
    return batch.holdJob(getJob(document), getForce(document));
}

auto releaseJob(BatchInterface& batch, rapidjson::Document& document) {
    return batch.releaseJob(getJob(document), getForce(document));
}

auto suspendJob(BatchInterface& batch, rapidjson::Document& document) {
    return batch.suspendJob(getJob(document), getForce(document));
}

auto resumeJob(BatchInterface& batch, rapidjson::Document& document) {
    return batch.resumeJob(getJob(document), getForce(document));
}

auto rescheduleRunningJobInQueue(BatchInterface& batch, rapidjson::Document& document) {
    return batch.rescheduleRunningJobInQueue(getJob(document), getForce(document));
}

}


#endif /* BOOST_PROXY_BATCHSYSTEM_JSON */