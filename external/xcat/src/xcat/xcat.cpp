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
XcatError check_errors(const std::string &o, std::error_code ec = {}) {
    XcatError error{ec, 0, ""};

    if (!o.length()) return error;

    rapidjson::Document d;
    if (d.Parse(o.c_str()).HasParseError() || !d.IsObject()) return error;


    std::string key = "";
    if (d.HasMember("errors"))
        key = "errors";
    else if (d.HasMember("error"))
        key = "error";

    if (key.empty()) return error;

    // found unknown error
    if (!error.ec) error.ec = error::api_error;


    if (d.HasMember("errorcode")) {
        if (d["errorcode"].IsString())
            error.error_code = std::stoi(d["errorcode"].GetString());
        else if (d["errorcode"].IsInt())
            error.error_code = d["errorcode"].GetInt();
    }

    if (key.length()) {
        if (d[key.c_str()].IsString()) {
            error.msg = d[key.c_str()].GetString();
        } else if (d[key.c_str()].IsArray()) {
            for (const auto& s : d[key.c_str()].GetArray())
                if (s.IsString()) error.msg += s.GetString();
        }
    }
    return error;
}


const char* to_cstr(error type) {
  switch (type) {
      case error::login_failed: return "login failed";
      case error::get_nodes_failed: return "get nodes failed";
      case error::get_groups_failed: return "get groups failed";
      case error::no_auth: return "no authentication set";
      case error::api_error: return "api error";
      case error::set_bootstate_failed: return "set bootstate failed";
      case error::get_bootstate_failed: return "get bootstate failed";
      case error::get_osimages_failed: return "get osimages failed";
      case error::set_group_attributes_failed: return "set group attributes failed";
      case error::set_nextboot_failed: return "set nextboot failed";
      case error::set_powerstate_failed: return "set powerstate failed";
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

void Xcat::set_token(std::string token, unsigned long int expires) {
    _token = token;
    _expires = expires;
}

void Xcat::set_credentials(std::string username, std::string password) {
    _username = username;
    _password = password;
}

void Xcat::get_token(std::function<void(std::string token, unsigned long int expires, XcatError ec)> cb) {
    _func({HttpMethod::POST, "/xcatws/tokens", "{\"userName\":\""+_username+"\",\"userPW\":\""+_password+"\"}", {{"Content-Type", "application/json"}}}, [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, 0, {resp.ec, 0, ""});
        } else if (resp.status_code == 201) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.HasMember("token") && indocument["token"].IsObject() && indocument["token"].HasMember("id") && indocument["token"]["id"].IsString()) {
                unsigned long int expires = 0;
                if (indocument["token"].HasMember("expire") && indocument["token"]["expire"].IsString()) {
                    time_t time;
                    if (timeToEpoch(indocument["token"]["expire"].GetString(), time, "%Y-%m-%d %H:%M:%S")) {
                        expires = static_cast<unsigned long int>(time);
                    }
                }
                std::string token = indocument["token"]["id"].GetString();
                cb(token, expires, {});
            } else {
                cb({}, 0, {error::login_failed, 0, ""});
            }
        } else {
            cb({}, 0, {error::login_failed, 0, ""});
        }
    });
}

bool Xcat::check_auth() {
    return !_token.empty() || (!_username.empty() && !_password.empty());
}

ApiCallRequest Xcat::add_auth(ApiCallRequest req, bool has_query_params) {
    if (!_token.empty()) {
        req.headers["X-Auth-Token"] = _token;
    } else if (!_username.empty() && !_password.empty()) {
        req.uri += std::string(has_query_params ? "&" : "?") +"userName="+_username+"&userPW="+_password;
    }
    return req;
}

void Xcat::get_nodes(const std::vector<std::string> &filter, std::function<void(std::map<std::string, NodeInfo>, XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::GET, filter.empty() ? "/xcatws/nodes/ALLRESOURCES" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",")), "", {}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, {resp.ec, 0, ""});
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
                    if (o.HasMember("groups") && o["groups"].IsString()) info.groups = split(o["groups"].GetString(), ',');

                    for (const auto& item: o) {
                        if (item.value.IsString()) info.extra[item.name.GetString()] = item.value.GetString();
                    }

                    nodes[info.name] = info;
                }

                cb(nodes, check_errors(resp.body));
            } else {
                cb({}, check_errors(resp.body, error::get_nodes_failed));
            }
        } else {
            cb({}, check_errors(resp.body, error::get_nodes_failed));
        }
    });
}

void Xcat::get_osimages(const std::vector<std::string> &filter, std::function<void(std::map<std::string, OsimageInfo>, XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::GET, filter.empty() ? "/xcatws/osimages/ALLRESOURCES" : (std::string("/xcatws/osimages/") + internal::joinString(filter.begin(), filter.end(), ",")), "", {}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, {resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.IsObject()) {
                std::map<std::string, OsimageInfo> nodes;
                for (const auto& p : indocument.GetObject()) {
                    OsimageInfo info;
                    info.name = p.name.GetString();

                    if (info.name == "info" && !p.value.IsObject()) {
                        // "Could not find any object definitions to display."
                        continue;
                    }

                    const auto& o = p.value.GetObject();
                    if (o.HasMember("profile") && o["profile"].IsString()) info.profile = o["profile"].GetString();
                    if (o.HasMember("osname") && o["osname"].IsString()) info.osname = o["osname"].GetString();
                    if (o.HasMember("osarch") && o["osarch"].IsString()) info.osarch = o["osarch"].GetString();
                    if (o.HasMember("osvers") && o["osvers"].IsString()) info.osvers = o["osvers"].GetString();
                    if (o.HasMember("provmethod") && o["provmethod"].IsString()) info.provmethod = o["provmethod"].GetString();

                    nodes[info.name] = info;
                }

                cb(nodes, check_errors(resp.body));
            } else {
                cb({}, check_errors(resp.body, error::get_osimages_failed));
            }
        } else {
            cb({}, check_errors(resp.body, error::get_osimages_failed));
        }
    });
}

void Xcat::get_bootstate(const std::vector<std::string> &filter, std::function<void(std::map<std::string, std::string>, XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::GET, filter.empty() ? "xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/bootstate"), "", {}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, {resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            rapidjson::Document indocument;
            indocument.Parse(resp.body);
            if (!indocument.HasParseError() && indocument.IsObject()) {
                std::map<std::string, std::string> nodes;
                for (const auto& p : indocument.GetObject()) {
                    std::string key = p.name.GetString();
                    if (key == "info" && !p.value.IsObject()) {
                        // "Could not find any object definitions to display."
                        continue;
                    }

                    const auto& o = p.value.GetObject();
                    std::string bootstate;
                    if (o.HasMember("bootstate") && o["bootstate"].IsString()) bootstate = o["bootstate"].GetString();
                    nodes[key] = bootstate;
                }

                cb(nodes, check_errors(resp.body));
            } else {
                cb({}, check_errors(resp.body, error::get_bootstate_failed));
            }
        } else {
            cb({}, check_errors(resp.body, error::get_bootstate_failed));
        }
    });
}

void Xcat::set_bootstate(const std::vector<std::string> &filter, std::string osimage, std::function<void(XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::PUT, filter.empty() ? "/xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/bootstate"), "{\"osimage\":\"" + osimage + "\"}", {{"Content-Type", "application/json"}}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            cb(check_errors(resp.body));
        } else {
            cb(check_errors(resp.body, error::set_bootstate_failed));
        }
    });
}

void Xcat::set_nextboot(const std::vector<std::string> &filter, std::string order, std::function<void(XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::PUT, filter.empty() ? "/xcatws/nodes/ALLRESOURCES/nextboot" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/nextboot"), "{\"order\":\"" + order + "\"}", {{"Content-Type", "application/json"}}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            cb(check_errors(resp.body));
        } else {
            cb(check_errors(resp.body, error::set_nextboot_failed));
        }
    });
}

void Xcat::set_powerstate(const std::vector<std::string> &filter, std::string action, std::function<void(XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::PUT, filter.empty() ? "/xcatws/nodes/ALLRESOURCES/power" : (std::string("/xcatws/nodes/") + internal::joinString(filter.begin(), filter.end(), ",") + "/power"), "{\"action\":\""+action+"\"}", {{"Content-Type", "application/json"}}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            cb(check_errors(resp.body));
        } else {
            cb(check_errors(resp.body, error::set_powerstate_failed));
        }
    });
}

void Xcat::set_group_attributes(const std::vector<std::string> &filter, const std::map<std::string, std::string>& attrs, std::function<void(XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);

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

    _func(add_auth({HttpMethod::PUT, "/xcatws/groups/" + internal::joinString(filter.begin(), filter.end(), ","), jsonToString(doc), {{"Content-Type", "application/json"}}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({resp.ec, 0, ""});
        } else if (resp.status_code == 200) {
            cb(check_errors(resp.body));
        } else {
            cb(check_errors(resp.body, error::set_group_attributes_failed));
        }
    });
}

void Xcat::get_groups(const std::vector<std::string> &filter, std::function<void(std::map<std::string, GroupInfo>, XcatError ec)> cb) {
    if (!check_auth()) throw std::system_error(error::no_auth);
    _func(add_auth({HttpMethod::GET, filter.empty() ? "/xcatws/groups/ALLRESOURCES" : (std::string("/xcatws/groups/") + internal::joinString(filter.begin(), filter.end(), ",")), "", {}}, false), [cb](ApiCallResponse resp){
        if (resp.ec) {
            cb({}, {resp.ec, 0, ""});
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

                cb(groups, check_errors(resp.body));
            } else {
                cb({}, check_errors(resp.body, error::get_groups_failed));
            }
        } else {
            cb({}, check_errors(resp.body, error::get_groups_failed));
        }
    });
}

}
