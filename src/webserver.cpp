#include "webserver.h"

// Report a failure
void fail(beast::error_code ec, char const* what) {
    std::cerr << what << ": " << ec.message() << "\n";
}

//////////////////////////// session ////////////////////////////

session::session(tcp::socket&& socket)
    : ws_(std::move(socket)) {
    // nothing to do
}

void session::run() {
    // We need to be executing within a strand to perform async operations
    // on the I/O objects in this session. Although not strictly necessary
    // for single-threaded contexts, this example code is written to be
    // thread-safe by default.
    net::dispatch(ws_.get_executor(),
        beast::bind_front_handler(
            &session::on_run,
            shared_from_this()));
}


void session::on_run() {
    // Set suggested timeout settings for the websocket
    ws_.set_option(
        websocket::stream_base::timeout::suggested(
            beast::role_type::server));

    // Set a decorator to change the Server of the handshake
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server,
                std::string(BOOST_BEAST_VERSION_STRING) +
                    " websocket-server-async");
        }));
    // Accept the websocket handshake
    ws_.async_accept(
        beast::bind_front_handler(
            &session::on_accept,
            shared_from_this()));
}


void session::on_accept(beast::error_code ec) {
    if(ec) {
        return fail(ec, "accept");
    }

    // Read a message
    do_read();
}


void session::do_read() {
    // Read a message into our buffer
    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            &session::on_read,
            shared_from_this()));
}


void session::on_read( beast::error_code ec,
              std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    // This indicates that the session was closed
    if(ec == websocket::error::closed) {
        return;
    }

    if(ec) {
        fail(ec, "read");
    }

    // mark debug remove
    std::cout << "Server input: " << static_cast<char*>(buffer_.data().data()) << std::endl;
    
    std::string answer = "Hello ";
    answer.append(static_cast<char*>(buffer_.data().data()));
    net::const_buffer answerBuffer2(static_cast<const void *>(answer.c_str()), answer.size());

    // Echo the message
    ws_.text(ws_.got_text());
    ws_.async_write(
        answerBuffer2,
        beast::bind_front_handler(
            &session::on_write,
            shared_from_this()));
}


void session::on_write(beast::error_code ec,
              std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if(ec) {
        return fail(ec, "write");
    }

    // Clear the buffer
    buffer_.consume(buffer_.size());

    // Do another read
    do_read();
}

//////////////////////////// listener ////////////////////////////

///// public
listener::listener(
        net::io_context& ioc,
        tcp::endpoint endpoint)
        : ioc_(ioc)
        , acceptor_(ioc) {
    beast::error_code ec;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if(ec) {
        fail(ec, "open");
        return;
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if(ec) {
        fail(ec, "set_option");
        return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if(ec) {
        fail(ec, "bind");
        return;
    }

    // Start listening for connections
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if(ec) {
        fail(ec, "listen");
        return;
    }
}


void listener::run() {
    do_accept();
}


///// private

void listener::do_accept() {
    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(
            &listener::on_accept,
            shared_from_this()));
}


void listener::on_accept(beast::error_code ec, tcp::socket socket) {
    if(ec) {
        fail(ec, "accept");
    } else {
        // Create the session and run it
        std::make_shared<session>(std::move(socket))->run();
    }

    // Accept another connection
    do_accept();
}