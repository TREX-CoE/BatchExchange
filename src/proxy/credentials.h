#ifndef BOOST_PROXY_CREDENTIALS
#define BOOST_PROXY_CREDENTIALS

#include <string>
#include <map>
#include "shared/string_view.h"
#include "shared/http.h"

namespace credentials {

using dict = std::map<std::string, std::pair<std::string, std::string>>;

void read(dict& creds, std::istream& in);

void write(const dict& creds, std::ostream &out);

std::string check_header(const dict& creds, string_view header);

}

#endif /* BOOST_PROXY_CREDENTIALS */