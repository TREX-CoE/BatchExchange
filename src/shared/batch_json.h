#ifndef BOOST_PROXY_BATCH_JSON
#define BOOST_PROXY_BATCH_JSON

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "batchsystem/json.h"

#include <vector>

namespace cw {
namespace helper {
namespace json {

using namespace cw::batch::json;

template <typename T>
rapidjson::Document serialize_wrap(const std::vector<T>& entry) {
    rapidjson::Document document;
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
    document.SetObject();

    rapidjson::Value entryArr;
    entryArr.SetArray();
    for (const auto& e : entry) {
            rapidjson::Document subdocument(&document.GetAllocator());
            serialize(e, subdocument);
            entryArr.PushBack(subdocument, allocator);
    }
    document.AddMember("data", entryArr, allocator);
    return document;
}

}
}
}

#endif /* BOOST_PROXY_BATCH_JSON */
