#ifndef BOOST_SHARED_HTTP
#define BOOST_SHARED_HTTP

#include <string>
#include <boost/utility/string_view.hpp>

namespace cw {
namespace http {

bool parse_auth_header(boost::string_view header, std::string& user, std::string& pass);

}
}


#endif /* BOOST_SHARED_HTTP */