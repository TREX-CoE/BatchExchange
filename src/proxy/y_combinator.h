#ifndef BOOST_Y_COMBINATOR
#define BOOST_Y_COMBINATOR

#include <functional>
#include <utility>

namespace cw {
namespace helper {

/**
 * @brief Ycombinator storing functor by copying.
 */
template <class F>
class y_combinator_result {
private:
    F f; // the lambda will be stored here
    
public:
    explicit y_combinator_result(F &&fun): f(std::forward<F>(fun)) {}

    // a forwarding operator():
    template <class... Args>
    decltype(auto) operator()(Args&&... args) const {
        // we pass ourselves to f, then the arguments.
        // note the standard proposal uses std::ref(*this) but for using recursive lambda in event handlers, that would cause lifetime issues
        // if wanting to use reference instead use like this:
        // auto almost_gcd = [](auto gcd, int a, int b) -> int { return b == 0 ? a : gcd(b, a % b); };
        // auto gcd = std::y_combinator(std::ref(almost_gcd));

        return f(*this, std::forward<Args>(args)...);
    }

    template <class... Args>
    decltype(auto) operator()(Args&&... args) {
        // we pass ourselves to f, then the arguments.
        // note the standard proposal uses std::ref(*this) but for using recursive lambda in event handlers, that would cause lifetime issues
        // if wanting to use reference instead use like this:
        // auto almost_gcd = [](auto gcd, int a, int b) -> int { return b == 0 ? a : gcd(b, a % b); };
        // auto gcd = std::y_combinator(std::ref(almost_gcd));

        return f(*this, std::forward<Args>(args)...);
    }
};

// helper function that deduces the type of the lambda:
template <class Fun>
y_combinator_result<std::decay_t<Fun>> y_combinator(Fun&& f) {
    return y_combinator_result<std::decay_t<Fun>>(std::forward<Fun>(f));
}

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
