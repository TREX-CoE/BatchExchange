#include "xcat.h"

#include <iostream>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>

#define RAPIDJSON_HAS_STDSTRING 1
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "internal/joinString.h"

namespace {

using namespace xcat;

static inline bool timeToEpoch(const std::string& isoDatetime, std::time_t& epoch, const char* format) {
	std::istringstream ss(isoDatetime);
	std::tm t{};
	ss >> std::get_time(&t, format);
	if (ss.fail()) return false;
	epoch = mktime(&t);
	return true;
}

/**
 * @brief Check json output for errors
 *
 * @param o output
 * @return 0 No errors
 * @return 1 Errors found
 */
int check_errors(const std::string &o) {
    if (!o.length())
        return 0;

    rapidjson::Document d;
    if (d.Parse(o.c_str()).HasParseError()) {
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
      case error::api_error: return "api error";
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






}

namespace xcat {

const std::error_category& error_category() noexcept {
    return error_cat;
}

std::error_code make_error_code(error e) {
  return {static_cast<int>(e), error_cat};
}

Xcat::Xcat(http_f func): _func(func) {}

void Xcat::set_token(std::string token) {
    _token = token;
}

void Xcat::login(std::string username, std::string password, std::function<void(TokenInfo token, std::error_code ec)> cb) {
    _func({HttpMethod::POST, "/xcatws/tokens", "{\"userName\":\""+username+"\",\"userPW\":\""+password+"\"}", {{"Content-Type", "application/json"}}}, [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, resp.ec);
        } else if (resp.status_code == 201) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.HasMember("token") && indocument["token"].IsObject() && indocument["token"].HasMember("id") && indocument["token"]["id"].IsString()) {
                TokenInfo info;
                info.token = indocument["token"]["id"].GetString();
                info.expires = 0;
                if (indocument["token"].HasMember("expire") && indocument["token"]["expire"].IsString()) {
                    time_t time;
                    if (timeToEpoch(indocument["token"]["expire"].GetString(), time, "%Y-%m-%d %H:%M:%S")) {
                        time = static_cast<unsigned long int>(info.expires);
                    }
                }
                cb(info, {});
            } else {
                cb({}, error::login_failed);
            }
        } else {
            cb({}, error::login_failed);
        }
    });
}

void Xcat::get_nodes(std::function<void(std::map<std::string, NodeInfo>, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, "/xcatws/nodes/ALLRESOURCES", "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, resp.ec);
        } else if (resp.status_code == 200) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.IsObject()) {
                std::map<std::string, NodeInfo> nodes;
                for (const auto& p : indocument.GetObject()) {
                    NodeInfo info;
                    info.name = p.name.GetString();

                    const auto& o = p.value.GetObject();
                    if (o.HasMember("groups") && o["groups"].IsString()) info.groups = o["groups"].GetString();
                    nodes[info.name] = info;
                }

                cb(nodes, {});
            } else {
                cb({}, error::login_failed);
            }
        } else {
            cb({}, error::login_failed);
        }
    });
}

void Xcat::get_os_images(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, filter.empty() ? "xcatws/osimages/ALLRESOURCES" : (std::string("xcatws/osimages/") + internal::joinString(filter.begin(), filter.end(), ",")), "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::get_bootstate(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, filter.empty() ? "xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/bootstate"), "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::set_bootstate(const std::vector<std::string> &filter, BootState bootState, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::PUT, filter.empty() ? "xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/bootstate"), "{\"osimage\":\"" + bootState.osImage + "\"}", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::power_nodes(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::PUT, filter.empty() ? "xcatws/nodes/ALLRESOURCES/power" : (std::string("xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/power"), "{\"action\":\"reset\"}", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::set_group_attributes(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::PUT, "xcatws/groups/" + internal::joinString(filter.begin(), filter.end(), ","), "{\"action\":\"reset\"}", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::get_groups(std::string group, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, group.empty() ? "xcatws/groups/" : ("xcatws/groups/" + group), "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

}
