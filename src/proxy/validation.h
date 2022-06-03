#ifndef BOOST_VALIDATION
#define BOOST_VALIDATION

#include <exception>

namespace cw {
namespace helper {

/**
 * \brief Exception for validation error
 * 
 */
class ValidationError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

}
}

#endif /* BOOST_VALIDATION */
