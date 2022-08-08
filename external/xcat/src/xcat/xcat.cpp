#include "xcat.h"

#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "internal/joinString.h"

namespace {

using namespace xcat;

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
                func(resp, {HttpMethod::GET, uri, "", {}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    token=resp.body;
                } else {
                    state=State::Done;
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
    std::string cred_header;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    GetNodes(http_f& func_, std::string cred_header_): func(func_), cred_header(cred_header_) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, "xcatws/nodes", "", {{"X-Auth-Token", cred_header}}});
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
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class GetOsImages {
private:
    http_f& func;
    std::string cred_header;
    std::string uri;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    GetOsImages(http_f& func_, std::string cred_header_, const std::vector<std::string>& filter_): func(func_), cred_header(cred_header_), uri(filter_.empty() ? "xcatws/osimages/ALLRESOURCES" : (std::string("xcatws/osimages/") + internal::joinString(filter_.begin(), filter_.end(), ","))) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, uri, "", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class GetBootState {
private:
    http_f& func;
    std::string cred_header;
    std::string uri;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    GetBootState(http_f& func_, std::string cred_header_, const std::vector<std::string>& filter_): func(func_), cred_header(cred_header_), uri(filter_.empty() ? "xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("xcatws/nodes/") + internal::joinString(filter_.begin(), filter_.end(), ",") + "/bootstate")) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, uri, "", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class SetBootState {
private:
    http_f& func;
    std::string cred_header;
    BootState bootState;
    std::string uri;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    SetBootState(http_f& func_, std::string cred_header_, const std::vector<std::string>& filter_, BootState bootState_): func(func_), cred_header(cred_header_), bootState(bootState_), uri(filter_.empty() ? "xcatws/nodes/ALLRESOURCES/bootstate" : (std::string("xcatws/nodes/") + internal::joinString(filter_.begin(), filter_.end(), ",") + "/bootstate")) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::PUT, uri, "{\"osimage\":\"" + bootState.osImage + "\"}", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class PowerNodes {
private:
    http_f& func;
    std::string cred_header;
    std::string uri;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    PowerNodes(http_f& func_, std::string cred_header_, const std::vector<std::string>& filter_): func(func_), cred_header(cred_header_), uri(filter_.empty() ? "xcatws/nodes/ALLRESOURCES/power" : (std::string("xcatws/nodes/") + internal::joinString(filter_.begin(), filter_.end(), ",") + "/power")) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::PUT, uri, "{\"action\":\"reset\"}", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class SetGroupAttributes {
private:
    http_f& func;
    std::string cred_header;
    std::string uri;
    ApiCallResponse resp;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    SetGroupAttributes(http_f& func_, std::string cred_header_, const std::vector<std::string>& filter_): func(func_), cred_header(cred_header_), uri("xcatws/groups/" + internal::joinString(filter_.begin(), filter_.end(), ",")) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::PUT, uri, "{\"action\":\"reset\"}", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

class GetGroups {
private:
    http_f& func;
    std::string cred_header;
    ApiCallResponse resp;
    std::string uri;
    enum class State {
        Start,
        Waiting,
        Done,
    };
    State state;
public:
    GetGroups(http_f& func_, std::string cred_header_, std::string group): func(func_), cred_header(cred_header_), uri(group.empty() ? "xcatws/groups/" : ("xcatws/groups/" + group)) {}

    bool operator()(std::string& output) {
        switch (state) {
			case State::Start: {
                func(resp, {HttpMethod::GET, uri, "", {{"X-Auth-Token", cred_header}}});
				state = State::Waiting;
			}
			// fall through
			case State::Waiting: {
                if (resp.status_code == 0) {
                    return false;
                } else if (resp.status_code==200) {
					state=State::Done;
                    // TODO utils::check_errors(output)
                    output=resp.body;
                } else {
                    state=State::Done;
                    throw std::system_error(error::api_error);
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

Xcat::Xcat(http_f func): _func(func) {}

void Xcat::set_token(std::string token) {
    _token = token;
}

std::function<bool(std::string&)> Xcat::login(std::string username, std::string password) { return Login(_func, username, password); }
std::function<bool(std::string&)> Xcat::get_nodes() {
    if (_token.empty()) throw std::system_error(error::no_token);
    return GetNodes(_func, _token);
}
std::function<bool(std::string&)> Xcat::get_os_images(const std::vector<std::string> &filter) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return GetOsImages(_func, _token, filter);
}
std::function<bool(std::string&)> Xcat::get_bootstate(const std::vector<std::string> &filter) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return GetBootState(_func, _token, filter);
}
std::function<bool(std::string&)> Xcat::set_bootstate(const std::vector<std::string> &filter, BootState state) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return SetBootState(_func, _token, filter, state);
}
std::function<bool(std::string&)> Xcat::power_nodes(const std::vector<std::string> &filter) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return PowerNodes(_func, _token, filter);
}
std::function<bool(std::string&)> Xcat::set_group_attributes(const std::vector<std::string> &filter) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return SetGroupAttributes(_func, _token, filter);
}
std::function<bool(std::string&)> Xcat::get_groups(std::string group) {
    if (_token.empty()) throw std::system_error(error::no_token);
    return GetGroups(_func, _token, group);
}

}
