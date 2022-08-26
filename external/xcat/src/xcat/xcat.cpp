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

std::string jsonToString(const rapidjson::Document& document) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    return buffer.GetString();
}

std::vector<std::string> split(const std::string& s, char del) {
   std::vector<std::string> out;
   std::string token;
   std::istringstream stream(s);
   while (std::getline(stream, token, del)) out.push_back(std::move(token));
   return out;
}


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
      case error::get_nodes_failed: return "get nodes failed";
      case error::get_groups_failed: return "get groups failed";
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

                    if (info.name == "info" && !p.value.IsObject()) {
                        // "Could not find any object definitions to display."
                        continue;
                    }

                    const auto& o = p.value.GetObject();
                    if (o.HasMember("postscripts") && o["postscripts"].IsString()) info.postscripts = o["postscripts"].GetString();
                    if (o.HasMember("postbootscripts") && o["postbootscripts"].IsString()) info.postbootscripts = o["postbootscripts"].GetString();
                    if (o.HasMember("installnic") && o["installnic"].IsString()) info.installnic = o["installnic"].GetString();
                    if (o.HasMember("primarynic") && o["primarynic"].IsString()) info.primarynic = o["primarynic"].GetString();
                    if (o.HasMember("mac") && o["mac"].IsString()) info.mac = o["mac"].GetString();
                    if (o.HasMember("groups") && o["groups"].IsString()) info.groups = o["groups"].GetString();
                    nodes[info.name] = info;
                }

                cb(nodes, {});
            } else {
                cb({}, error::get_nodes_failed);
            }
        } else {
            cb({}, error::get_nodes_failed);
        }
    });
}

void Xcat::get_os_images(const std::vector<std::string> &filter, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, filter.empty() ? "/xcatws/osimages/ALLRESOURCES" : (std::string("/xcatws/osimages/") + internal::joinString(filter.begin(), filter.end(), ",")), "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
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

void Xcat::set_bootstate(const std::vector<std::string> &filter, std::string osimage, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::PUT, filter.empty() ? "/xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/bootstate"), "{\"osimage\":\"" + osimage + "\"}", {{"Content-Type", "application/json"}, {"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::power_nodes(const std::vector<std::string> &filter, std::string action, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::PUT, filter.empty() ? "/xcatws/nodes/ALLRESOURCES/power" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/power"), "{\"action\":\""+action+"\"}", {{"Content-Type", "application/json"}, {"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::set_group_attributes(const std::vector<std::string> &filter, const std::map<std::string, std::string>& attrs, std::function<void(std::string, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);

    rapidjson::Document doc;
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();
    doc.SetObject();
    {
        for (const auto& p : attrs) {
            rapidjson::Value key(p.first.c_str(), allocator);
            rapidjson::Value val(p.second.c_str(), allocator);
            doc.AddMember(key, val, allocator);
        }
    }

    _func({HttpMethod::PUT, "/xcatws/groups/" + internal::joinString(filter.begin(), filter.end(), ","), jsonToString(doc), {{"Content-Type", "application/json"}, {"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.status_code == 200) {
            cb(resp.body, {});
        } else {
            cb("", resp.ec);
        }
    });
}

void Xcat::get_groups(std::string group, std::function<void(std::map<std::string, GroupInfo>, std::error_code ec)> cb) {
    if (_token.empty()) throw std::system_error(error::no_token);
    _func({HttpMethod::GET, group.empty() ? "/xcatws/groups/ALLRESOURCES" : ("/xcatws/groups/" + group), "", {{"X-Auth-Token", _token}}}, [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, resp.ec);
        } else if (resp.status_code == 200) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.IsObject()) {
                std::map<std::string, GroupInfo> groups;
                for (const auto& p : indocument.GetObject()) {
                    GroupInfo info;
                    info.name = p.name.GetString();

                    if (info.name == "info" && !p.value.IsObject()) {
                        // "Could not find any object definitions to display."
                        continue;
                    }

                    const auto& o = p.value.GetObject();
                    if (o.HasMember("members") && o["members"].IsString()) info.members = split(o["members"].GetString(), ',');
                    if (o.HasMember("mgt") && o["mgt"].IsString()) info.mgt = o["mgt"].GetString();
                    if (o.HasMember("netboot") && o["netboot"].IsString()) info.netboot = o["netboot"].GetString();
                    groups[info.name] = info;
                }

                cb(groups, {});
            } else {
                cb({}, error::get_groups_failed);
            }
        } else {
            cb({}, error::get_groups_failed);
        }
    });
}

}
