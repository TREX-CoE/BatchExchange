#ifndef BOOST_PROXY_SHA512
#define BOOST_PROXY_SHA512

#include <string>
#include <boost/utility/string_view.hpp>

namespace cw {
namespace helper {

std::string sha512_hash(boost::string_view input);

}
}

#endif /* BOOST_PROXY_SHA512 */