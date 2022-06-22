#ifndef BOOST_PROXY_BATCHSYSTEM_JSON
#define BOOST_PROXY_BATCHSYSTEM_JSON

#include "batchsystem/batchsystem.h"
#include "proxy/uri.h"
#include "shared/splitString.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <boost/optional.hpp>

namespace {

using namespace cw::batch;

const std::string queryComma = ",";

bool queryToBool(const std::string& input, std::string& err) {
    if (input == "false" || input == "0" || input == "no") {
        return false;
    } else if (input == "" || input == "true" || input == "1" || input == "yes") {
        return true;
    } else {
        err =  "not a valid bool";
        return false;
    }
}

std::string getForce(const rapidjson::Document& document, bool& out) {
        if (document.IsObject() && document.HasMember("force")) {
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
using namespace cw::helper::uri;

boost::optional<JobOptions> runJob(const rapidjson::Document& document, std::string& err) {
    JobOptions opts;
    if (!document.IsObject()) {
        err = "body is not a json object";
        return {};
    }

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
    if (document.HasMember("tasks")) {
            auto& tasks = document["tasks"];
            if (!tasks.IsInt()) {
                err = "tasks is not an int";
                return {};
            }
            int nnodes = tasks.GetInt();
            if (nnodes < 1) {
                err = "tasks has to be atleast 1";
                return {};
            }
            opts.numberTasks = static_cast<uint32_t>(nnodes);
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


boost::optional<std::tuple<std::string, bool>> deleteJobById(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) { err = "path not including job id"; return {}; }
        std::get<0>(t) = uri.path[0];
        if (uri.query.count("force")) {
            std::get<1>(t) = queryToBool(uri.query.at("force"), err); 
            if (!err.empty()) return {};
        } else {
            std::get<1>(t) = false;
        }
    } else {
        if (!document.IsObject()) {
            err = "body is not a json object";
            return {};
        }
        err = getJob(document, std::get<0>(t));
        if (!err.empty()) return {};
        err = getForce(document, std::get<1>(t));
        if (!err.empty()) return {};
    }
    return {t};
}

boost::optional<std::tuple<std::string, bool>> deleteJobByUser(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (!uri.query.count("user")) {
            err = "query not including user"; return {};
        }
        std::get<0>(t) = uri.query.at("user");
        if (uri.query.count("force")) {
            std::get<1>(t) = queryToBool(uri.query.at("force"), err); 
            if (!err.empty()) return {};
        } else {
            std::get<1>(t) = false;
        }
    } else {
        if (!document.IsObject()) {
            err = "body is not a json object";
            return {};
        }
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
    }
    return {t};
}

boost::optional<std::tuple<std::string, NodeChangeState, bool, std::string, bool>> changeNodeState(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, NodeChangeState, bool, std::string, bool> t;
    std::get<2>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            err = "node is not given";
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        err = getNode(document, std::get<0>(t));
        if (!err.empty()) return {};
    }

    if (!document.IsObject()) {
        err = "body is not a json object";
        return {};
    }

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

boost::optional<std::tuple<std::string, QueueState, bool>> setQueueState(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, QueueState, bool> t;
    std::get<2>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            err = "queue is not given";
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        err = getQueue(document, std::get<0>(t));
        if (!err.empty()) return {};
    }

    if (!document.IsObject()) {
        err = "body is not a json object";
        return {};
    }

    std::string state;
    err = getState(document, state);
    if (!err.empty()) return {};
    err = convertQueue(state, std::get<1>(t));
    if (!err.empty()) return {};

    err = getForce(document, std::get<2>(t));
    if (!err.empty()) return {};

    return {t};
}

boost::optional<std::tuple<std::string, bool, std::string, bool>> setNodeComment(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, bool, std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            err = "node is not given";
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        err = getNode(document, std::get<0>(t));
        if (!err.empty()) return {};
    }

    if (!document.IsObject()) {
        err = "body is not a json object";
        return {};
    }

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

boost::optional<std::tuple<std::string, bool>> holdJob(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            err = "job is not given";
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        err = getJob(document, std::get<0>(t));
        if (!err.empty()) return {};
    } else {
        err = "body is not a json object";
        return {};
    }

    err = getForce(document, std::get<1>(t));
    if (!err.empty()) return {};

    return {t};
}

constexpr auto releaseJob = holdJob;
constexpr auto suspendJob = holdJob;
constexpr auto resumeJob = holdJob;
constexpr auto rescheduleRunningJobInQueue = holdJob;


std::vector<std::string> getJobs(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::vector<std::string> jobs;
    if (uri.has_value() && uri.query.count("filterJobs")) {
        std::string filter = uri.query.at("filterJobs");
        cw::helper::splitString(filter, queryComma, [&jobs, &filter](size_t start, size_t end){
            jobs.push_back(filter.substr(start, end));
            return true;
        });
    } else if (document.IsObject() && document.HasMember("filterJobs")) {
            if (!document["filterJobs"].IsArray()) {
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

std::vector<std::string> getNodes(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    std::vector<std::string> nodes;
    if (uri.has_value() && uri.query.count("filterNodes")) {
        std::string filter = uri.query.at("filterNodes");
        cw::helper::splitString(filter, queryComma, [&nodes, &filter](size_t start, size_t end){
            nodes.push_back(filter.substr(start, end));
            return true;
        });
    } else if (document.IsObject() && document.HasMember("filterNodes")) {
            if (!document["filterNodes"].IsArray()) {
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

boost::optional<std::tuple<std::string, std::set<std::string>, std::string>> usersAdd(const rapidjson::Document& document, const Uri& uri, bool isPatch, std::string& err) {
    std::tuple<std::string, std::set<std::string>, std::string> t;
    if (uri.has_value() && uri.path.size() == 1) {
        std::get<0>(t) = uri.path[0];
    } else {
        if (!document.IsObject()) {
            err = "body is not a json object";
            return {};
        }
        if (!document.HasMember("user")) {
            err = "user not given";
            return {};
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            err = "user is not a string";
            return {};
        }
        std::get<0>(t) = user.GetString();
    }

    if (document.IsObject() && document.HasMember("password")) {
        auto& password = document["password"];
        if (!password.IsString()) {
            err = "password is not a string";
            return {};
        }
        std::get<2>(t) = password.GetString();
    } else if (!isPatch) {
        err = "password not given";
        return {};
    } else {
        std::get<2>(t) = "";
    }

    if (document.IsObject() && document.HasMember("scopes")) {
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
            std::string scope = v.GetString();
            if (!v.IsString()) {
                err = "Empty string is not a valid scope";
                return {};
            }
            std::get<1>(t).insert(std::move(scope));
        }
    } else {
        std::get<1>(t).insert(""); // sentinel to mark no scopes given
    }

    return {t};
}

std::string usersDelete(const rapidjson::Document& document, const Uri& uri, std::string& err) {
    if (uri.has_value() && uri.path.size() == 1) {
        return uri.path[0];
    } else if (document.IsObject()) {
        if (!document.HasMember("user")) {
            err = "user not given";
            return "";
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            err = "user is not a string";
            return "";
        }
        return user.GetString();
    } else {
        err = "body is not a json object";
        return "";
    }
}


}


#endif /* BOOST_PROXY_BATCHSYSTEM_JSON */