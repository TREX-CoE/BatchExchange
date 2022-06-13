#include "sha512.h"
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace cw {
namespace helper {

std::string sha512_hash(boost::string_view input) {
    EVP_MD_CTX * evpCtx = EVP_MD_CTX_new ();
    EVP_DigestInit_ex (evpCtx, EVP_sha512 (), NULL);
    EVP_DigestUpdate(evpCtx, input.data(), input.size());
    unsigned int len;
    unsigned char result[SHA512_DIGEST_LENGTH] = {0};
    EVP_DigestFinal_ex (evpCtx, result, &len);

    std::stringstream ss;
    for(unsigned int i = 0; i < len; i++) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    return ss.str();
}

}
}