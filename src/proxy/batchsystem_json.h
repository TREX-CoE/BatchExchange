#ifndef BOOST_PROXY_BATCHSYSTEM_JSON
#define BOOST_PROXY_BATCHSYSTEM_JSON

#include "batchsystem/batchsystem.h"

#include <boost/optional.hpp>

namespace {

using namespace cw::batch;

std::string getForce(const rapidjson::Document& document, bool& out) {
        if (document.HasMember("force")) {
                if (!document["force"].IsBool()) return "force is not a bool";
                out = document["force"].GetBool();
        }
        return "";
}

std::string getJob(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("job")) return "job not given";
        auto& job = document["job"];
        if (!job.IsString()) return "job is not a string";
        out = std::string(job.GetString());
        return "";
}

std::string getNode(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("node")) return "No node given";
        auto& node = document["node"];
        if (!node.IsString()) return "Node is not a string";
        out = std::string(node.GetString());
        return "";
}

std::string getQueue(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("queue")) return "queue not given";
        auto& queue = document["queue"];
        if (!queue.IsString()) return "queue is not a string";
        out = std::string(queue.GetString());
        return "";
}

std::string getState(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("state")) return "state not given";
        auto& queue = document["state"];
        if (!queue.IsString()) return "state is not a string";
        out = std::string(queue.GetString());
        return "";
}

std::string convertQueue(const std::string& str, QueueState& state) {
        if (str == "open") {
                state = QueueState::Open;
        } else if (str == "closed") {
                state = QueueState::Closed;
        } else if (str == "inactive") {
                state = QueueState::Inactive;
        } else if (str == "draining") {
                state = QueueState::Draining;
        } else {
                return "Invalid queue state";
        }
        return "";
}

std::string convertNodeChange(const std::string& str, NodeChangeState& state) {
        if (str == "resume") {
                state = NodeChangeState::Resume;
        } else if (str == "drain") {
                state = NodeChangeState::Drain;
        } else if (str == "undrain") {
                state = NodeChangeState::Undrain;
        } else {
                return "Invalid node state";
        }
        return "";
}

}


namespace cw_proxy_batch {

using namespace cw::batch;

boost::optional<JobOptions> runJob(const rapidjson::Document& document, std::string& err) {
    JobOptions opts;
    if (!document.HasMember("path")) {
        err = "path not given";
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


boost::optional<std::tuple<std::string, bool>> deleteJobById(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, bool> t;
    err = getJob(document, std::get<0>(t));
    if (!err.empty()) return {};
    err = getForce(document, std::get<1>(t));
    if (!err.empty()) return {};
    return {t};
}

boost::optional<std::tuple<std::string, bool>> deleteJobByUser(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, bool> t;
    if (!document.HasMember("user")) {
        err = "user not given";
        return {};
    }
    auto& user = document["user"];
    if (!user.IsString()) {
        err = "user is not a string";
        return {};
    }
    err = getForce(document, std::get<1>(t));
    if (!err.empty()) return {};
    return {t};
}

boost::optional<std::tuple<std::string, NodeChangeState, bool, std::string, bool>> changeNodeState(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, NodeChangeState, bool, std::string, bool> t;
    err = getNode(document, std::get<0>(t));
    if (!err.empty()) return {};

    std::string state;
    err = getState(document, state);
    if (!err.empty()) return {};
    err = convertNodeChange(state, std::get<1>(t));
    if (!err.empty()) return {};

    err = getForce(document, std::get<2>(t));
    if (!err.empty()) return {};

    if (document.HasMember("reason")) {
            auto& reason = document["reason"];
            if (!reason.IsString()) {
                err = "reason is not a string";
                return {};
            }
            std::get<3>(t) = reason.GetString();
    }
    if (document.HasMember("append")) {
            if (!document["append"].IsBool()) {
                    err = "append is not a bool";
                    return {};
            }
            std::get<4>(t) = document["append"].GetBool();
    } else {
            std::get<4>(t) = false;
    }

    return {t};
}

boost::optional<std::tuple<std::string, QueueState, bool>> setQueueState(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, QueueState, bool> t;
    err = getQueue(document, std::get<0>(t));
    if (!err.empty()) return {};

    std::string state;
    err = getState(document, state);
    if (!err.empty()) return {};
    err = convertQueue(state, std::get<1>(t));
    if (!err.empty()) return {};

    err = getForce(document, std::get<2>(t));
    if (!err.empty()) return {};

    return {t};
}

boost::optional<std::tuple<std::string, bool, std::string, bool>> setNodeComment(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, bool, std::string, bool> t;

    err = getNode(document, std::get<0>(t));
    if (!err.empty()) return {};

    err = getForce(document, std::get<1>(t));
    if (!err.empty()) return {};

    if (!document.HasMember("comment")) {
        err = "comment not given";
        return {};
    }
    auto& comment = document["comment"];
    if (!comment.IsString()) {
        err = "comment is not a string";
        return {};
    }
    std::get<2>(t) = comment.GetString();

    if (document.HasMember("append")) {
        if (!document["append"].IsBool()) {
                err = "append is not a bool";
                return {};
        }
        std::get<3>(t) = document["append"].GetBool();
    } else {
        std::get<3>(t) = false;
    }

    return {t};
}

boost::optional<std::tuple<std::string, bool>> holdJob(const rapidjson::Document& document, std::string& err) {
    std::tuple<std::string, bool> t;

    err = getJob(document, std::get<0>(t));
    if (!err.empty()) return {};

    err = getForce(document, std::get<1>(t));
    if (!err.empty()) return {};

    return {t};
}

constexpr auto releaseJob = holdJob;
constexpr auto suspendJob = holdJob;
constexpr auto resumeJob = holdJob;
constexpr auto rescheduleRunningJobInQueue = holdJob;


std::vector<std::string> getJobs(const rapidjson::Document& document, std::string& err) {
    std::vector<std::string> jobs;
    if (document.HasMember("filterJobs")) {
            if (document["filterJobs"].IsArray()) {
                    err = "filterJobs is not an array";
                    return jobs;
            }
            for (const auto& v : document["filterJobs"].GetArray()) {
                if (!v.IsString()) {
                        err = "filterJobs entry is not a string";
                        return jobs;
                }
                jobs.push_back(v.GetString());
            }
    }
    return jobs;
}

std::vector<std::string> getNodes(const rapidjson::Document& document, std::string& err) {
    std::vector<std::string> nodes;
    if (document.HasMember("filterNodes")) {
            if (document["filterNodes"].IsArray()) {
                    err = "filterNodes is not an array";
                    return nodes;
            }
            for (const auto& v : document["filterNodes"].GetArray()) {
                if (!v.IsString()) {
                        err = "filterNodes entry is not a string";
                        return nodes;
                }
                nodes.push_back(v.GetString());
            }
    }
    return nodes;
}

boost::optional<std::tuple<std::string, std::set<std::string>, std::string>> usersAdd(const rapidjson::Document& document, std::string username, std::string& err) {
    std::tuple<std::string, std::set<std::string>, std::string> t;

    if (username.empty()) {
        if (!document.HasMember("user")) {
            err = "user not given";
            return {};
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            err = "user is not a string";
            return {};
        }
        username = user.GetString();
    }
    std::get<0>(t) = std::move(username);

    if (!document.HasMember("password")) {
        err = "password not given";
        return {};
    }
    auto& password = document["password"];
    if (!password.IsString()) {
        err = "password is not a string";
        return {};
    }
    std::get<2>(t) = password.GetString();

    if (document.HasMember("scopes")) {
        auto& scopes = document["scopes"];
        if (!scopes.IsArray()) {
            err = "scopes is not an array";
            return {};
        }
        for (const auto& v : scopes.GetArray()) {
            if (!v.IsString()) {
                err = "scopes array item is not an string";
                return {};
            }
            std::get<1>(t).insert(v.GetString());
        }
    }

    return {t};
}

}


#endif /* BOOST_PROXY_BATCHSYSTEM_JSON */