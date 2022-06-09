#ifndef BOOST_PROXY_SERVER
#define BOOST_PROXY_SERVER

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <thread>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/make_unique.hpp>
#include <boost/optional.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/buffers_iterator.hpp>

namespace cw {
namespace proxy {

namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if(ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

// Echoes back all received WebSocket messages.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived, class Handler>
class websocket_session : public Handler::websocket_session
{
private:
    std::vector<std::string> queue_;
    boost::asio::io_context& ioc_;

    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    beast::flat_buffer buffer_;

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void
    do_accept(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Set suggested timeout settings for the websocket
        derived().ws().set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // Set a decorator to change the Server of the handshake
        derived().ws().set_option(
            websocket::stream_base::decorator(
            [](websocket::response_type& res)
            {
                res.set(http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " advanced-server-flex");
            }));

        // Accept the websocket handshake
        derived().ws().async_accept(
            req,
            beast::bind_front_handler(
                &websocket_session::on_accept,
                derived().shared_from_this()));
    }

    void
    do_read()
    {
        // Read a message into our buffer
        derived().ws().async_read(
            buffer_,
            beast::bind_front_handler(
                &websocket_session::on_read,
                derived().shared_from_this()));
    }

    void on_accept(beast::error_code ec) {
        // Handle the error, if any
        if(ec)
            return fail(ec, "accept");

        // Read a message
        do_read();
    }

    void on_read(beast::error_code ec, std::size_t) {
        // Handle the error, if any
        if(ec)
            return fail(ec, "read");

        // Handle message
        Handler::handle_socket(*this, ioc_, beast::buffers_to_string(buffer_.data()));


        // Clear the buffer
        buffer_.consume(buffer_.size());

        // Read another message
        do_read();
    }

    void on_send(std::string s) {
        // Always add to queue
        queue_.push_back(s);

        // Are we already writing?
        if(queue_.size() > 1)
            return;

        // We are not currently writing, so send this immediately
        derived().ws().async_write(
            net::buffer(queue_.front()),
            beast::bind_front_handler(
                &websocket_session::on_write,
                derived().shared_from_this()));
    }

    void on_write(beast::error_code ec, size_t) {
        // Handle the error, if any
        if(ec)
            return fail(ec, "write");

        // Remove the string from the queue
        queue_.erase(queue_.begin());

        // Send the next message if any
        if(!queue_.empty())
            derived().ws().async_write(
                net::buffer(queue_.front()),
                beast::bind_front_handler(
                    &websocket_session::on_write,
                    derived().shared_from_this()));
    }


    // Start the asynchronous operation
    template<class Body, class Allocator>
    void
    run(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }

    template<class H, class Body, class Allocator>
    friend void make_websocket_session(beast::tcp_stream stream, http::request<Body, http::basic_fields<Allocator>> req, boost::asio::io_context& ioc_);
    template<class H, class Body, class Allocator>
    friend void make_websocket_session(beast::ssl_stream<beast::tcp_stream> stream, http::request<Body, http::basic_fields<Allocator>> req, boost::asio::io_context& ioc_);

protected:
    websocket_session(boost::asio::io_context& ioc): ioc_(ioc) {}
public:

    void send(std::string s) {
        // Post our work to the strand, this ensures
        // that the members of `this` will not be
        // accessed concurrently.
        net::post(
            derived().ws().get_executor(),
            beast::bind_front_handler(
                &websocket_session::on_send,
                derived().shared_from_this(),
                std::move(s)));
    }
};



//------------------------------------------------------------------------------

// Handles a plain WebSocket connection
template <class Handler>
class plain_websocket_session
    : public websocket_session<plain_websocket_session<Handler>, Handler>
    , public std::enable_shared_from_this<plain_websocket_session<Handler>>
{
    websocket::stream<beast::tcp_stream> ws_;

public:
    // Create the session
    explicit
    plain_websocket_session(
        beast::tcp_stream&& stream,
        boost::asio::io_context& ioc)
        : websocket_session<plain_websocket_session<Handler>, Handler>(ioc), ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<beast::tcp_stream>&
    ws()
    {
        return ws_;
    }
};

//------------------------------------------------------------------------------

// Handles an SSL WebSocket connection
template <class Handler>
class ssl_websocket_session
    : public websocket_session<ssl_websocket_session<Handler>, Handler>
    , public std::enable_shared_from_this<ssl_websocket_session<Handler>>
{
    websocket::stream<
        beast::ssl_stream<beast::tcp_stream>> ws_;

public:
    // Create the ssl_websocket_session
    explicit
    ssl_websocket_session(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        boost::asio::io_context& ioc)
        : websocket_session<ssl_websocket_session<Handler>, Handler>(ioc), ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<
        beast::ssl_stream<beast::tcp_stream>>&
    ws()
    {
        return ws_;
    }
};

template<class Handler, class Body, class Allocator>
void
make_websocket_session(
    beast::tcp_stream stream,
    http::request<Body, http::basic_fields<Allocator>> req,
    boost::asio::io_context& ioc_)
{
    std::make_shared<plain_websocket_session<Handler>>(
        std::move(stream), ioc_)->run(std::move(req));
}

template<class Handler, class Body, class Allocator>
void
make_websocket_session(
    beast::ssl_stream<beast::tcp_stream> stream,
    http::request<Body, http::basic_fields<Allocator>> req,
    boost::asio::io_context& ioc_)
{
    std::make_shared<ssl_websocket_session<Handler>>(
        std::move(stream), ioc_)->run(std::move(req));
}


//------------------------------------------------------------------------------

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived, class Handler>
class http_session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    // This queue is used for HTTP pipelining.
    class queue
    {
        // The type-erased, saved work item
        struct work
        {
            virtual ~work() = default;
            virtual void operator()() = 0;
        };

        http_session& self_;
        std::vector<std::unique_ptr<work>> items_;

    public:
        explicit
        queue(http_session& self)
            : self_(self)
        {
            static_assert(Handler::limit() > 0, "queue limit must be positive");
            items_.reserve(Handler::limit());
        }

        // Returns `true` if we have reached the queue limit
        bool
        is_full() const
        {
            return items_.size() >= Handler::limit();
        }

        // Called when a message finishes sending
        // Returns `true` if the caller should initiate a read
        bool
        on_write()
        {
            BOOST_ASSERT(! items_.empty());
            auto const was_full = is_full();
            items_.erase(items_.begin());
            if(! items_.empty())
                (*items_.front())();
            return was_full;
        }

        // Called by the HTTP handler to send a response.
        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg)
        {
            // This holds a work item
            struct work_impl : work
            {
                http_session& self_;
                http::message<isRequest, Body, Fields> msg_;

                work_impl(
                    http_session& self,
                    http::message<isRequest, Body, Fields>&& msg)
                    : self_(self)
                    , msg_(std::move(msg))
                {
                }

                void
                operator()()
                {
                    http::async_write(
                        self_.derived().stream(),
                        msg_,
                        beast::bind_front_handler(
                            &http_session::on_write,
                            self_.derived().shared_from_this(),
                            msg_.need_eof()));
                }
            };

            // Allocate and store the work
            items_.push_back(
                boost::make_unique<work_impl>(self_, std::move(msg)));

            // If there was no previous work, start this one
            if(items_.size() == 1)
                (*items_.front())();
        }
    };

    queue queue_;

    // The parser is stored in an optional container so we can
    // construct it from scratch it at the beginning of each new message.
    boost::optional<http::request_parser<http::string_body>> parser_;



protected:
    beast::flat_buffer buffer_;
    net::io_context& ioc_;
    bool websocket_support_;

public:
    // Construct the session
    http_session(
        beast::flat_buffer buffer, net::io_context& ioc, bool websocket_support)
        : queue_(*this)
        , buffer_(std::move(buffer))
        , ioc_(ioc)
        , websocket_support_(websocket_support)
    {
    }

protected:
    void
    do_read()
    {
        // Construct a new parser for each message
        parser_.emplace();

        // Apply a reasonable limit to the allowed size
        // of the body in bytes to prevent abuse.
        parser_->body_limit(Handler::body_limit());

        // Set the timeout.
        beast::get_lowest_layer(
            derived().stream()).expires_after(Handler::timeout());

        // Read a request using the parser-oriented interface
        http::async_read(
            derived().stream(),
            buffer_,
            *parser_,
            beast::bind_front_handler(
                &http_session::on_read,
                derived().shared_from_this()));
    }

    void
    on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return derived().do_eof();

        if(ec)
            return fail(ec, "read");

        // See if it is a WebSocket Upgrade
        if(websocket_support_ && websocket::is_upgrade(parser_->get()))
        {
            // Disable the timeout.
            // The websocket::stream uses its own timeout settings.
            beast::get_lowest_layer(derived().stream()).expires_never();

            // Create a websocket session, transferring ownership
            // of both the socket and the HTTP request.
            return make_websocket_session<Handler>(
                derived().release_stream(),
                parser_->release(),
                ioc_);
        }

        // Send the response
        Handler::handle_request(derived().shared_from_this(), parser_->release());

        // If we aren't at the queue limit, try to pipeline another request
        if(! queue_.is_full())
            do_read();
    }

    void
    on_write(bool close, beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        }

        // Inform the queue that a write completed
        if(queue_.on_write())
        {
            // Read another request
            do_read();
        }
    }
public:

    net::io_context& ioc() { return ioc_; }

    template<bool isRequest, class Body, class Fields>
    void
    send(http::message<isRequest, Body, Fields>&& msg)
    {
        return queue_(std::forward<http::message<isRequest, Body, Fields>>(msg));
    }

};

//------------------------------------------------------------------------------

// Handles a plain HTTP connection
template <class Handler>
class plain_http_session
    : public http_session<plain_http_session<Handler>, Handler>
    , public std::enable_shared_from_this<plain_http_session<Handler>>
{
    beast::tcp_stream stream_;

public:
    std::string buf;

    // Create the session
    plain_http_session(
        beast::tcp_stream&& stream,
        beast::flat_buffer&& buffer,
        net::io_context& ioc,
        bool websocket_support)
        : http_session<plain_http_session<Handler>, Handler>(
            std::move(buffer), ioc, websocket_support)
        , stream_(std::move(stream))
    {
    }

    // Start the session
    void
    run()
    {
        this->do_read();
    }

    // Called by the base class
    beast::tcp_stream&
    stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::tcp_stream
    release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void
    do_eof()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Handles an SSL HTTP connection
template <class Handler>
class ssl_http_session
    : public http_session<ssl_http_session<Handler>, Handler>
    , public std::enable_shared_from_this<ssl_http_session<Handler>>
{
    beast::ssl_stream<beast::tcp_stream> stream_;

public:
    std::string buf;

    // Create the http_session
    ssl_http_session(
        beast::tcp_stream&& stream,
        ssl::context& ctx,
        beast::flat_buffer&& buffer,
        net::io_context& ioc,
        bool websocket_support)
        : http_session<ssl_http_session<Handler>, Handler>(
            std::move(buffer), ioc, websocket_support)
        , stream_(std::move(stream), ctx)
    {
    }

    // Start the session
    void
    run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(Handler::timeout());

        // Perform the SSL handshake
        // Note, this is the buffered version of the handshake.
        stream_.async_handshake(
            ssl::stream_base::server,
            http_session<ssl_http_session<Handler>, Handler>::buffer_.data(),
            beast::bind_front_handler(
                &ssl_http_session::on_handshake,
                std::enable_shared_from_this<ssl_http_session<Handler>>::shared_from_this()));
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>&
    stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>
    release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void
    do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(Handler::timeout());

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &ssl_http_session::on_shutdown,
                std::enable_shared_from_this<ssl_http_session<Handler>>::shared_from_this()));
    }

private:
    void
    on_handshake(
        beast::error_code ec,
        std::size_t bytes_used)
    {
        if(ec)
            return fail(ec, "handshake");

        // Consume the portion of the buffer used by the handshake
        http_session<ssl_http_session<Handler>, Handler>::buffer_.consume(bytes_used);

        http_session<ssl_http_session<Handler>, Handler>::do_read();
    }

    void
    on_shutdown(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Detects SSL handshakes
template <class Handler>
class detect_session : public std::enable_shared_from_this<detect_session<Handler>>
{
    beast::tcp_stream stream_;
    ssl::context& ctx_;
    beast::flat_buffer buffer_;
    net::io_context& ioc_;
    bool force_ssl_;
    bool websocket_support_;

public:
    explicit
    detect_session(
        tcp::socket&& socket,
        ssl::context& ctx,
        net::io_context& ioc,
        bool force_ssl,
        bool websocket_support)
        : stream_(std::move(socket))
        , ctx_(ctx)
        , ioc_(ioc)
        , force_ssl_(force_ssl)
        , websocket_support_(websocket_support)
    {
    }

    // Launch the detector
    void
    run()
    {
        // Set the timeout.
        stream_.expires_after(Handler::timeout());

        beast::async_detect_ssl(
            stream_,
            buffer_,
            beast::bind_front_handler(
                &detect_session::on_detect,
                this->shared_from_this()));
    }

    void
    on_detect(beast::error_code ec, boost::tribool result)
    {
        if(ec)
            return fail(ec, "detect");

        if(result)
        {
            // Launch SSL session
            std::make_shared<ssl_http_session<Handler>>(
                std::move(stream_),
                ctx_,
                std::move(buffer_),
                ioc_,
                websocket_support_)->run();
            return;
        }

        if (force_ssl_) return;

        // Launch plain session
        std::make_shared<plain_http_session<Handler>>(
            std::move(stream_),
            std::move(buffer_),
            ioc_,
            websocket_support_)->run();
    }
};

// Accepts incoming connections and launches the sessions
template <class Handler>
class listener : public std::enable_shared_from_this<listener<Handler>>
{
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    bool force_ssl_;
    bool websocket_support_;

public:
    listener(
        net::io_context& ioc,
        ssl::context& ctx,
        tcp::endpoint endpoint,
        bool force_ssl,
        bool websocket_support)
        : ioc_(ioc)
        , ctx_(ctx)
        , acceptor_(net::make_strand(ioc))
        , force_ssl_(force_ssl)
        , websocket_support_(websocket_support)
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                std::enable_shared_from_this<listener<Handler>>::shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if(ec)
        {
            fail(ec, "accept");
        }
        else
        {
            // Create the detector http_session and run it
            std::make_shared<detect_session<Handler>>(
                std::move(socket),
                ctx_,
                ioc_,
                force_ssl_,
                websocket_support_)->run();
        }

        // Accept another connection
        do_accept();
    }
};

}
}

#endif /* BOOST_PROXY_SERVER */