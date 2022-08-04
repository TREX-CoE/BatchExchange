#include "xcat.h"

#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace {

/**
 * @brief Check json output for errors
 *
 * @param o output
 * @return 0 No errors
 * @return 1 Errors found
 */
int utils::check_errors(const std::string &o) {
    if (!o.length())
        return 0;

    rapidjson::Document d;
    if (d.Parse(o.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    if (!d.IsObject())
        return 0;

    std::string key = "";
    if (d.HasMember("errors"))
        key = "errors";
    else if (d.HasMember("error"))
        key = "error";

    const char *errorKey = key.c_str();
    const char *errorCodeKey = "errorcode";
    int errorCode = 0;
    if (d.HasMember(errorCodeKey)) {
        if (d[errorCodeKey].IsString())
            errorCode = std::stoi(d[errorCodeKey].GetString());
        else if (d[errorCodeKey].IsInt())
            errorCode = d[errorCodeKey].GetInt();
    }

    if (errorCode != 0)
        std::cerr << "Error Code " << errorCode << " - ";

    if (key.length()) {
        if (d[errorKey].IsString()) {
            std::string err = d[errorKey].GetString();
            if (err.length()) {
                std::cerr << err << std::endl;
                return 1;
            }
        } else if (d[errorKey].IsArray()) {
            auto err = d[errorKey].GetArray();
            for (rapidjson::SizeType i = 0; i < err.Size(); i++)
                if (err[i].IsString())
                    std::cerr << err[i].GetString() << std::endl;
        }
    }
    return 0;
}


const char* to_cstr(error type) {
  switch (type) {
      case error::login_failed: return "login failed";
      case error::no_token: return "no token for authentication set";
      default: return "(unrecognized error)";
  }
}

struct ErrCategory : std::error_category
{

  const char* name() const noexcept {
    return "xcat";
  }
 
  std::string message(int ev) const {
    return to_cstr(static_cast<error>(ev));
  }
};

const ErrCategory error_cat {};

class Login {
private:
    http_f& func;
    ApiCallResponse resp;
    std::string uri;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    Login(http_f& func_, std::string username, std::string password): func(func_), uri("xcatws/tokens?userName="+username+"&userPW="+password) {}

    bool operator()(std::string& token) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, uri});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    token=resp.body;
                } else {
                    throw std::system_error(error::login_failed);
				}
			}
            // fall through
			case State::Done: {
                return true;
			}
			default: assert(false && "invalid state");
        }
    }
};

class GetNodes {
private:
    http_f& func;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    GetNodes(http_f& func_): func(func_) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, "xcatws/nodes", {}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    output=resp.body;
                } else {
                    throw std::system_error(error::get_nodes_failed);
				}
			}
            // fall through
			case State::Done: {
                return true;
			}
			default: assert(false && "invalid state");
        }
    }
};

}

namespace xcat {

const std::error_category& error_category() noexcept {
    return error_cat;
}

std::error_code make_error_code(error e) {
  return {static_cast<int>(e), error_cat};
}

void Xcat::set_token(std::string token) {
    _cred_header = "X-Auth-Token:" + token;
}

std::function<bool(std::string&)> Xcat::login(std::string username, std::string password) { return Login(_func, username, password); }
std::function<bool(std::string&)> Xcat::get_nodes() {
    if (_cred_header.empty()) throw std::system_error(error::no_token);
    return GetNodes(_func);
}


/**
 * @brief Get information of all available nodes
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_nodes(std::string &output) {
    int res = session->call("GET", "xcatws/nodes", output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get os images
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_os_images(const std::vector<std::string> &filter, std::string &output) {
    std::string response, imageRange = "ALLRESOURCES";

    if (filter.size())
        imageRange = utils::join_vector_to_string(filter, ",");

    int res = session->call("GET", "xcatws/osimages/" + imageRange, output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get names of os images
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_os_image_names(std::vector<std::string> &output) {
    std::string response;
    std::vector<std::string> images;
    if (get_os_images(images, response) != 0)
        return 1;

    rapidjson::Document d;

    d.Parse(response.c_str());

    for (auto &i : d.GetObject()) {
        output.push_back(i.name.GetString());
    }

    std::sort(output.begin(), output.end());

    return 0;
}

/**
 * @brief Get os images
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_bootstate(const std::vector<std::string> &filter, std::string &output) {
    // this uri does not provide a way to query all nodes at once -> fetch all nodes and join to {noderange}
    std::string nodeRange = "";
    if (filter.size())
        nodeRange = utils::join_vector_to_string(filter, ",");
    else {
        std::string nodeList;
        if (get_nodes(nodeList) != 0)
            return 1;

        rapidjson::Document d;
        d.Parse(nodeList.c_str());

        auto list = d.GetArray();
        for (rapidjson::SizeType i = 0; i < list.Size(); i++) {
            if (list[i].IsString()) {
                if (i != 0)
                    nodeRange += ",";
                nodeRange += list[i].GetString();
            }
        }
    }
    int res = session->call("GET", "xcatws/nodes/" + nodeRange + "/bootstate", output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Set os image
 *
 * @param filter filter
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_os_image(const std::vector<std::string> &filter, std::string osImage) {
    if (!filter.size() || !osImage.length())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/bootstate", response, "{\"osimage\":\"" + osImage + "\"}");

    if (utils::check_errors(response) || res != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

/**
 * @brief Reboot nodes
 *
 * @param filter filter
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::reboot_nodes(const std::vector<std::string> &filter) {
    if (!filter.size())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/nodes/" + utils::join_vector_to_string(filter, ",") + "/power", response, "{\"action\":\"reset\"}");

    if (utils::check_errors(response) || res != 0)
        return 1;
    std::cout << response << std::endl;
    return 0;
}

/**
 * @brief Set attributes of group
 *
 * @param group name of group
 * @param attributes json attributes
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_group_attributes(std::string group, const std::string &attributes) {
    if (!group.length())
        return 1;
    std::string response;
    int res = session->call("PUT", "xcatws/groups/" + group, response, attributes);

    if (utils::check_errors(response) || res != 0)
        return 1;

    std::cout << response << std::endl;

    return 0;
}

/**
 * @brief Set attributes of nodes
 *
 * @param nodes list of nodes
 * @param attributes json attributes
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::set_node_attributes(const std::vector<std::string> &nodes, const std::string &attributes) {
    if (!nodes.size())
        return 1;
    std::string nodeRange;
    nodeRange = utils::join_vector_to_string(nodes, ",");

    std::string response;
    int res = session->call("PUT", "xcatws/groups/" + nodeRange, response, attributes);

    if (utils::check_errors(response) || res != 0)
        return 1;

    std::cout << response << std::endl;

    return 0;
}

/**
 * @brief Get names of all groups
 *
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group_names(std::vector<std::string> &output) {
    std::string response;
    std::vector<std::string> images;
    int res = session->call("GET", "xcatws/groups/", response);

    if (utils::check_errors(response) || res != 0)
        return 1;

    rapidjson::Document d;
    if (d.Parse(response.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }
    auto groups = d.GetArray();
    for (rapidjson::SizeType i = 0; i < groups.Size(); i++) {
        if (groups[i].IsString())
            output.push_back(groups[i].GetString());
    }

    return 0;
}

/**
 * @brief Get attributes of group
 *
 * @param group group
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group(std::string group, std::string &output) {
    int res = session->call("GET", "xcatws/groups/" + group, output);

    if (res != 0 || utils::check_errors(output))
        return 1;

    return 0;
}

/**
 * @brief Get all members of group
 *
 * @param group group
 * @param output output
 * @return 0 Success
 * @return 1 Error
 */
int CXCat::get_group_members(std::string group, std::vector<std::string> &output) {
    std::string response;
    if (get_group(group, response) != 0)
        return 1;

    rapidjson::Document d;
    if (d.Parse(response.c_str()).HasParseError()) {
        std::cerr << INVALID_JSON_ERROR_MSG << std::endl;
        return 1;
    }

    auto c = group.c_str();
    // members are always saved as a comma-separated string
    if (d.IsObject() && d.HasMember(c) && d[c].HasMember("members") && d[c]["members"].IsString())
        utils::str_split(d[c]["members"].GetString(), ",", output);

    return 0;
}

}