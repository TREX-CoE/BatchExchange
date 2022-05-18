#ifndef BOOST_PROXY_POLL
#define BOOST_PROXY_POLL

#include <boost/asio/post.hpp>
#include <functional>

namespace cw {
namespace helper {
namespace asio {

class Poll : public std::enable_shared_from_this<Poll> {
public:
    using callback = std::function<void(Poll& poll)>;

    static std::shared_ptr<Poll> create(boost::asio::io_context& io_context, callback func) {
        std::shared_ptr<Poll> handler{new Poll(io_context, func)};
        handler->pollCallback();
        return handler;
    }

    void stop() {
        _cancelled = true;
    }

private:
    // hide constructor to avoid stack allocation -> lifetime possible shorter than io_context callback
    Poll(boost::asio::io_context& io_context, callback func): _io_context(io_context), _func(func) {}
    boost::asio::io_context& _io_context;
    bool _cancelled{false};
    callback _func;
    void pollCallback() {
        if (_cancelled) return;
        auto handler = shared_from_this();
        _io_context.post([handler](){
            if (handler->_cancelled) return;
            handler->_func(*handler);
            if (handler->_cancelled) return;
            handler->pollCallback();
        });
    }
};

}
}
}

#endif /* BOOST_PROXY_POLL */
