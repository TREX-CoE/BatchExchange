#ifndef BOOST_Y_COMBINATOR
#define BOOST_Y_COMBINATOR

#include <functional>
#include <utility>

namespace cw {
namespace helper {

/**
 * @brief Ycombinator storing functor in shared_ptr.
 */
template <class F>
class y_combinator_shared_result {
private:
    std::shared_ptr<F> f;
public:
    explicit y_combinator_shared_result(F &&fun): f(std::shared_ptr<F>{new F(std::forward<F>(fun))}) {}
    template <class... Args>
    decltype(auto) operator()(Args&&... args) const { return (*f)(*this, std::forward<Args>(args)...); }
    template <class... Args>
    decltype(auto) operator()(Args&&... args) { return (*f)(*this, std::forward<Args>(args)...); }
};

template <class Fun>
y_combinator_shared_result<std::decay_t<Fun>> y_combinator_shared(Fun&& f) {
    return y_combinator_shared_result<std::decay_t<Fun>>{std::forward<Fun>(f)};
}


}
}

#endif /* BOOST_Y_COMBINATOR */
