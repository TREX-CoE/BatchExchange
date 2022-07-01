#ifndef BOOST_PROXY_BATCHSYSTEM_JSON
#define BOOST_PROXY_BATCHSYSTEM_JSON

#include "batchsystem/batchsystem.h"
#include "proxy/uri.h"
#include "proxy/error.h"
#include "shared/splitString.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <boost/optional.hpp>

namespace {

using namespace cw::batch;
using namespace cw::error;

const std::string queryComma = ",";

bool queryToBool(const std::string& input, bool& succ) {
    if (input == "false" || input == "0" || input == "no") {
        succ = true;
        return false;
    } else if (input == "" || input == "true" || input == "1" || input == "yes") {
        succ = true;
        return true;
    } else {
        succ = false;
        return false;
    }
}

std::error_code getForce(const rapidjson::Document& document, bool& out) {
        if (document.IsObject() && document.HasMember("force")) {
                if (!document["force"].IsBool()) return error_type::force_not_bool;
                out = document["force"].GetBool();
        }
        return {};
}

std::error_code getJob(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("job")) return error_type::job_missing;
        auto& job = document["job"];
        if (!job.IsString()) return error_type::job_not_string;
        out = std::string(job.GetString());
        return {};
}

std::error_code getNode(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("node")) return error_type::node_missing;
        auto& node = document["node"];
        if (!node.IsString()) return error_type::node_not_string;
        out = std::string(node.GetString());
        return {};
}

std::error_code getQueue(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("queue")) return error_type::queue_missing;
        auto& queue = document["queue"];
        if (!queue.IsString()) return error_type::queue_not_string;
        out = std::string(queue.GetString());
        return {};
}

std::error_code getState(const rapidjson::Document& document, std::string& out) {
        if (!document.HasMember("state")) return error_type::state_missing;
        auto& queue = document["state"];
        if (!queue.IsString()) return error_type::state_not_string;
        out = std::string(queue.GetString());
        return {};
}

std::error_code convertQueue(const std::string& str, QueueState& state) {
        if (str == "open") {
                state = QueueState::Open;
        } else if (str == "closed") {
                state = QueueState::Closed;
        } else if (str == "inactive") {
                state = QueueState::Inactive;
        } else if (str == "draining") {
                state = QueueState::Draining;
        } else {
                return error_type::queue_state_unknown;
        }
        return {};
}

std::error_code convertNodeChange(const std::string& str, NodeChangeState& state) {
        if (str == "resume") {
                state = NodeChangeState::Resume;
        } else if (str == "drain") {
                state = NodeChangeState::Drain;
        } else if (str == "undrain") {
                state = NodeChangeState::Undrain;
        } else {
                return error_type::node_state_unknown;
        }
        return {};
}

}


namespace cw_proxy_batch {

using namespace cw::batch;
using namespace cw::helper::uri;

boost::optional<JobOptions> runJob(const rapidjson::Document& document, std::error_code& ec) {
    JobOptions opts;
    if (!document.IsObject()) {
        ec = error_type::body_not_object;
        return {};
    }

    if (!document.HasMember("path")) {
        ec = error_type::job_path_missing;
        return {};
    } else {
        auto& path = document["path"];
        if (!path.IsString()) {
                ec = error_type::job_path_not_string;
                return {};
        }
        opts.path = std::string(path.GetString());
    }

    if (document.HasMember("nodes")) {
            auto& nodes = document["nodes"];
            if (!nodes.IsInt()) {
                ec = error_type::job_nodes_not_int;
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                ec = error_type::job_nodes_smaller_1;
                return {};
            }
            opts.numberNodes = static_cast<uint32_t>(nnodes);
    }
    if (document.HasMember("nodesMax")) {
            auto& nodes = document["nodesMax"];
            if (!nodes.IsInt()) {
                ec = error_type::job_nodesMax_not_int;
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                ec = error_type::job_nodesMax_smaller_1;
                return {};
            }
            opts.numberNodesMax = static_cast<uint32_t>(nnodes);
    }
    if (document.HasMember("tasks")) {
            auto& tasks = document["tasks"];
            if (!tasks.IsInt()) {
                ec = error_type::job_tasks_not_int;
                return {};
            }
            int nnodes = tasks.GetInt();
            if (nnodes < 1) {
                ec = error_type::job_tasks_smaller_1;
                return {};
            }
            opts.numberTasks = static_cast<uint32_t>(nnodes);
    }
    if (document.HasMember("gpus")) {
            auto& nodes = document["gpus"];
            if (!nodes.IsInt()) {
                ec = error_type::job_gpus_not_int;
                return {};
            }
            int nnodes = nodes.GetInt();
            if (nnodes < 1) {
                ec = error_type::job_gpus_smaller_1;
                return {};
            }
            opts.numberNodesMax = static_cast<uint32_t>(nnodes);
    }
    return {opts};
}


boost::optional<std::tuple<std::string, bool>> deleteJobById(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) { ec = error_type::rest_path_not_including_job_id; return {}; }
        std::get<0>(t) = uri.path[0];
        if (uri.query.count("force")) {
            bool succ;
            std::get<1>(t) = queryToBool(uri.query.at("force"), succ); 
            if (!succ) {
                ec = error_type::force_unknown;
                return {};
            }
        } else {
            std::get<1>(t) = false;
        }
    } else {
        if (!document.IsObject()) {
            ec = error_type::body_not_object;
            return {};
        }
        ec = getJob(document, std::get<0>(t));
        if (ec) return {};
        ec = getForce(document, std::get<1>(t));
        if (ec) return {};
    }
    return {t};
}

boost::optional<std::tuple<std::string, bool>> deleteJobByUser(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (!uri.query.count("user")) {
            ec = error_type::rest_query_user_missing;
            return {};
        }
        std::get<0>(t) = uri.query.at("user");
        if (uri.query.count("force")) {
            bool succ;
            std::get<1>(t) = queryToBool(uri.query.at("force"), succ); 
            if (!succ) {
                ec = error_type::force_unknown;
                return {};
            }
        } else {
            std::get<1>(t) = false;
        }
    } else {
        if (!document.IsObject()) {
            ec = error_type::body_not_object;
            return {};
        }
        if (!document.HasMember("user")) {
            ec = error_type::user_missing;
            return {};
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            ec = error_type::user_not_string;
            return {};
        }
        ec = getForce(document, std::get<1>(t));
        if (ec) return {};
    }
    return {t};
}

boost::optional<std::tuple<std::string, NodeChangeState, bool, std::string, bool>> changeNodeState(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, NodeChangeState, bool, std::string, bool> t;
    std::get<2>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            ec = error_type::rest_path_not_including_node_id;
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        ec = getNode(document, std::get<0>(t));
        if (ec) return {};
    }

    if (!document.IsObject()) {
        ec = error_type::body_not_object;
        return {};
    }

    std::string state;
    ec = getState(document, state);
    if (ec) return {};
    ec = convertNodeChange(state, std::get<1>(t));
    if (ec) return {};

    ec = getForce(document, std::get<2>(t));
    if (ec) return {};

    if (document.HasMember("reason")) {
            auto& reason = document["reason"];
            if (!reason.IsString()) {
                ec = error_type::reason_not_string;
                return {};
            }
            std::get<3>(t) = reason.GetString();
    }
    if (document.HasMember("append")) {
            if (!document["append"].IsBool()) {
                    ec = error_type::append_not_bool;
                    return {};
            }
            std::get<4>(t) = document["append"].GetBool();
    } else {
            std::get<4>(t) = false;
    }

    return {t};
}

boost::optional<std::tuple<std::string, QueueState, bool>> setQueueState(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, QueueState, bool> t;
    std::get<2>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            ec = error_type::rest_path_not_including_queue_id;
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        ec = getQueue(document, std::get<0>(t));
        if (ec) return {};
    }

    if (!document.IsObject()) {
        ec = error_type::body_not_object;
        return {};
    }

    std::string state;
    ec = getState(document, state);
    if (ec) return {};
    ec = convertQueue(state, std::get<1>(t));
    if (ec) return {};

    ec = getForce(document, std::get<2>(t));
    if (ec) return {};

    return {t};
}

boost::optional<std::tuple<std::string, bool, std::string, bool>> setNodeComment(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, bool, std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            ec = error_type::rest_path_not_including_node_id;
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        ec = getNode(document, std::get<0>(t));
        if (ec) return {};
    }

    if (!document.IsObject()) {
        ec = error_type::body_not_object;
        return {};
    }

    ec = getForce(document, std::get<1>(t));
    if (ec) return {};

    if (!document.HasMember("comment")) {
        ec = error_type::comment_missing;
        return {};
    }
    auto& comment = document["comment"];
    if (!comment.IsString()) {
        ec = error_type::comment_not_string;
        return {};
    }
    std::get<2>(t) = comment.GetString();

    if (document.HasMember("append")) {
        if (!document["append"].IsBool()) {
                ec = error_type::append_not_bool;
                return {};
        }
        std::get<3>(t) = document["append"].GetBool();
    } else {
        std::get<3>(t) = false;
    }

    return {t};
}

boost::optional<std::tuple<std::string, bool>> holdJob(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::tuple<std::string, bool> t;
    std::get<1>(t) = false;

    if (uri.has_value()) {
        if (uri.path.size() != 1) {
            ec = error_type::rest_path_not_including_job_id;
            return {}; 
        }
        std::get<0>(t) = uri.path[0];
    } else if (document.IsObject()) {
        ec = getJob(document, std::get<0>(t));
        if (ec) return {};
    } else {
        ec = error_type::body_not_object;
        return {};
    }

    ec = getForce(document, std::get<1>(t));
    if (ec) return {};

    return {t};
}

constexpr auto releaseJob = holdJob;
constexpr auto suspendJob = holdJob;
constexpr auto resumeJob = holdJob;
constexpr auto rescheduleRunningJobInQueue = holdJob;


std::vector<std::string> getJobs(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::vector<std::string> jobs;
    if (uri.has_value() && uri.query.count("filterJobs")) {
        std::string filter = uri.query.at("filterJobs");
        cw::helper::splitString(filter, queryComma, [&jobs, &filter](size_t start, size_t end){
            jobs.push_back(filter.substr(start, end));
            return true;
        });
    } else if (document.IsObject() && document.HasMember("filterJobs")) {
            if (!document["filterJobs"].IsArray()) {
                    ec = error_type::filterJobs_not_array;
                    return jobs;
            }
            for (const auto& v : document["filterJobs"].GetArray()) {
                if (!v.IsString()) {
                        ec = error_type::filterJobs_not_string_array;
                        return jobs;
                }
                jobs.push_back(v.GetString());
            }
    }
    return jobs;
}

std::vector<std::string> getNodes(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    std::vector<std::string> nodes;
    if (uri.has_value() && uri.query.count("filterNodes")) {
        std::string filter = uri.query.at("filterNodes");
        cw::helper::splitString(filter, queryComma, [&nodes, &filter](size_t start, size_t end){
            nodes.push_back(filter.substr(start, end));
            return true;
        });
    } else if (document.IsObject() && document.HasMember("filterNodes")) {
            if (!document["filterNodes"].IsArray()) {
                    ec = error_type::filterNodes_not_array;
                    return nodes;
            }
            for (const auto& v : document["filterNodes"].GetArray()) {
                if (!v.IsString()) {
                        ec = error_type::filterNodes_not_string_array;
                        return nodes;
                }
                nodes.push_back(v.GetString());
            }
    }
    return nodes;
}

boost::optional<std::tuple<std::string, std::set<std::string>, std::string>> usersAdd(const rapidjson::Document& document, const Uri& uri, bool isPatch, std::error_code& ec) {
    std::tuple<std::string, std::set<std::string>, std::string> t;
    if (uri.has_value() && uri.path.size() == 1) {
        std::get<0>(t) = uri.path[0];
    } else {
        if (!document.IsObject()) {
            ec = error_type::body_not_object;
            return {};
        }
        if (!document.HasMember("user")) {
            ec = error_type::user_missing;
            return {};
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            ec = error_type::user_not_string;
            return {};
        }
        std::get<0>(t) = user.GetString();
    }

    if (document.IsObject() && document.HasMember("password")) {
        auto& password = document["password"];
        if (!password.IsString()) {
            ec = error_type::password_not_string;
            return {};
        }
        std::get<2>(t) = password.GetString();
    } else if (!isPatch) {
        ec = error_type::password_missing;
        return {};
    } else {
        std::get<2>(t) = "";
    }

    if (document.IsObject() && document.HasMember("scopes")) {
        auto& scopes = document["scopes"];
        if (!scopes.IsArray()) {
            ec = error_type::scopes_not_array;
            return {};
        }
        for (const auto& v : scopes.GetArray()) {
            if (!v.IsString()) {
                ec = error_type::scope_invalid;
                return {};
            }
            std::string scope = v.GetString();
            if (!v.IsString()) {
                ec = error_type::scope_invalid;
                return {};
            }
            std::get<1>(t).insert(std::move(scope));
        }
    } else {
        std::get<1>(t).insert(""); // sentinel to mark no scopes given
    }

    return {t};
}

std::string usersDelete(const rapidjson::Document& document, const Uri& uri, std::error_code& ec) {
    if (uri.has_value() && uri.path.size() == 1) {
        return uri.path[0];
    } else if (document.IsObject()) {
        if (!document.HasMember("user")) {
            ec = error_type::user_missing;
            return "";
        }
        auto& user = document["user"];
        if (!user.IsString()) {
            ec = error_type::user_not_string;
            return "";
        }
        return user.GetString();
    } else {
        ec = error_type::body_not_object;
        return "";
    }
}


}


#endif /* BOOST_PROXY_BATCHSYSTEM_JSON */