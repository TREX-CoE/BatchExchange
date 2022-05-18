#ifndef BOOST_PROXY_PROXY_JSON
#define BOOST_PROXY_PROXY_JSON

#include <boost/beast/http.hpp>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <vector>
#include <string>

namespace cw {
namespace proxy {
namespace json {

rapidjson::Document generate_json_error(const std::string& type, const std::string& message, boost::beast::http::status status) {
    rapidjson::Document document;
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
    document.SetObject();
    {
        rapidjson::Value error;
        error.SetObject();
        error.AddMember("type", type, allocator);
        error.AddMember("message", message, allocator);
        error.AddMember("code", static_cast<int>(status), allocator);
        document.AddMember("error", error, allocator);
    }
    return document;
}

}
}
}

#endif /* BOOST_PROXY_PROXY_JSON */
