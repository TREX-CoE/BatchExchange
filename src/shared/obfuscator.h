#ifndef BOOST_PROXY_OBFUSCATOR
#define BOOST_PROXY_OBFUSCATOR

namespace cw {
namespace helper {

template <unsigned int N, unsigned char Key, typename T>
class obfuscator {
private:
    // store obfuscated string (using T to allow larger type than char to add padding between encoded chars)
    T m_data[N] = {0};
  
public:
    /*
     * Using constexpr ensures that the strings will be obfuscated in this
     * constructor function at compile time.
     */
    constexpr obfuscator(const char* data) {
        /*
         * Implement encryption algorithm here.
         * Here we have simple XOR algorithm.
         */
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = data[i] ^ Key;
        }
    }

    /*
     * deobfoscate decrypts the strings. Implement decryption algorithm here.
     * Here we have a simple XOR algorithm.
     */
    void deobfuscate(char * des) const{
        unsigned int i = 0;
        do {
            des[i] = static_cast<char>(m_data[i]) ^ Key;
            i++;
        } while (des[i-1]);
    }
};

}
}

#endif /* BOOST_PROXY_OBFUSCATOR */
