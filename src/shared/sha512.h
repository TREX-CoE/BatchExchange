#ifndef BOOST_PROXY_SHA512
#define BOOST_PROXY_SHA512

#include <string>
#include "shared/string_view.h"

namespace cw {
namespace helper {

std::string sha512_hash(string_view input);

}
}

#endif /* BOOST_PROXY_SHA512 */