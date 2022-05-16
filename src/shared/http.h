#ifndef BOOST_SHARED_HTTP
#define BOOST_SHARED_HTTP

#include <string>
#include "shared/string_view.h"

namespace cw {
namespace http {

bool parse_auth_header(string_view header, std::string& user, std::string& pass);

}
}


#endif /* BOOST_SHARED_HTTP */