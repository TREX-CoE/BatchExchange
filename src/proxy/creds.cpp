#include "proxy/creds.h"

namespace {

cw::helper::credentials::dict creds_;

}

namespace cw {
namespace creds {

void init(const cw::helper::credentials::dict& creds) {
    creds_ = creds;
}

const cw::helper::credentials::dict& get() {
    return creds_;
}

}
}