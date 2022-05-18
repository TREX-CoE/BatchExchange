#ifndef BOOST_PROXY_POLL_TIMER
#define BOOST_PROXY_POLL_TIMER

#include <boost/asio/steady_timer.hpp>
#include <functional>

namespace cw {
namespace helper {
namespace asio {

class PollTimer {
public:
    using callback = std::function<void(PollTimer& timer, const boost::system::error_code& ec)>;
    explicit PollTimer(boost::asio::io_context& io_context): _timer( io_context ) {}

    void set_interval(boost::posix_time::time_duration interval) {
        _interval = interval;
    }

    void stop() {
        _timer.cancel();
        _running = false;
        _func = nullptr;
    }
    
    void start(callback func) {
        if (_running) stop();
        _running = true;
        _func = func;
        this->wait();
    }

private:
    bool _running{false};
    boost::asio::deadline_timer _timer;
    boost::posix_time::time_duration _interval{boost::posix_time::millisec(100)};
    callback _func;
    void wait()
    {
        _timer.expires_from_now(_interval);
        _timer.async_wait([&](const boost::system::error_code& ec) {
            (void)ec;
            this->_func(*this, ec);
            if (_running) this->wait();
        });
    }
};

}
}
}

#endif /* BOOST_PROXY_POLL_TIMER */
