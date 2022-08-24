#include "proxy/xcat_http.h"
#include "proxy/error.h"

#include <boost/optional.hpp>
#include <boost/process.hpp>
#include <boost/asio.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace {

struct Request {
    tcp::resolver resolver;
    beast::tcp_stream stream;
    beast::flat_buffer buffer; // (Must persist between reads)
    http::request<http::string_body> req;
    http::response<http::string_body> res;
};

struct RequestSSL {
    tcp::resolver resolver;
    beast::ssl_stream<beast::tcp_stream> stream;
    beast::flat_buffer buffer; // (Must persist between reads)
    http::request<http::string_body> req;
    http::response<http::string_body> res;
};

boost::beast::http::verb convert_method(xcat::HttpMethod method) {
    switch (method) {
        case xcat::HttpMethod::GET: return boost::beast::http::verb::get;
        case xcat::HttpMethod::HEAD: return boost::beast::http::verb::head;
        case xcat::HttpMethod::POST: return boost::beast::http::verb::post;
        case xcat::HttpMethod::PUT: return boost::beast::http::verb::put;
        case xcat::HttpMethod::DELETE: return boost::beast::http::verb::delete_;
        case xcat::HttpMethod::CONNECT: return boost::beast::http::verb::connect;
        case xcat::HttpMethod::OPTIONS: return boost::beast::http::verb::options;
        case xcat::HttpMethod::TRACE: return boost::beast::http::verb::trace;
        case xcat::HttpMethod::PATCH: return boost::beast::http::verb::patch;
        default: return boost::beast::http::verb::unknown;
    }
}

}

namespace cw {
namespace proxy {
namespace xcat {

void runHttp(boost::asio::io_context& ioc_, ::xcat::ApiCallRequest req, std::function<void(::xcat::ApiCallResponse)> resp, unsigned int timeout_ms, std::string host, std::string port) {

    // Set up an HTTP GET request message
    auto method = convert_method(req.method);
    if (method == boost::beast::http::verb::unknown) {
        ::xcat::ApiCallResponse res;
        res.ec = cw::error::error_type::invalid_method;
        resp(res);
        return;
    }

    // run batchsystem command asynchronously
    std::shared_ptr<Request> boost_req{new Request{boost::asio::ip::tcp::resolver{make_strand(ioc_.get_executor())}, boost::beast::tcp_stream{make_strand(ioc_.get_executor())}, {}, {}, {}}};

    boost_req->req.version(11);
    boost_req->req.method(method);
    boost_req->req.target("http://"+host+"/"+req.uri);
    boost_req->req.set(http::field::host, host);
    boost_req->req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    std::cout << "target " << host+"/"+req.uri << std::endl;

    // Look up the domain name
    boost_req->resolver.async_resolve(
        host,
        port,
        [boost_req, resp, timeout_ms](beast::error_code ec, tcp::resolver::results_type results) {
            if (ec) {
                ::xcat::ApiCallResponse res;
                res.ec = ec;
                resp(res);
                return;
            }

            // Set a timeout on the operation
            boost_req->stream.expires_after(std::chrono::milliseconds(timeout_ms));


            boost_req->stream.async_connect(
                results,
                [boost_req, resp, timeout_ms](beast::error_code ec_connect, tcp::resolver::results_type::endpoint_type) {
                    if (ec_connect) {
                        ::xcat::ApiCallResponse res;
                        res.ec = ec_connect;
                        resp(res);
                        return;
                    }

                    // Set a timeout on the operation
                    boost_req->stream.expires_after(std::chrono::milliseconds(timeout_ms));

                    // Send the HTTP request to the remote host
                    http::async_write(boost_req->stream, boost_req->req,
                        [boost_req, resp](beast::error_code ec_write, std::size_t bytes_transferred_read) {
                            boost::ignore_unused(bytes_transferred_read);

                            if (ec_write) {
                                ::xcat::ApiCallResponse res;
                                res.ec = ec_write;
                                resp(res);
                                return;
                            }

                            // Receive the HTTP response
                            http::async_read(boost_req->stream, boost_req->buffer, boost_req->res,
                                [boost_req, resp](beast::error_code ec_read, std::size_t bytes_transferred_write) {
                                    boost::ignore_unused(bytes_transferred_write);

                                    if (ec_read) {
                                        ::xcat::ApiCallResponse res;
                                        res.ec = ec_read;
                                        resp(res);
                                        return;
                                    }

                                    // Write the message to standard out
                                    std::cout << boost_req->res << std::endl;

                                    // Gracefully close the socket
                                    boost_req->stream.socket().shutdown(tcp::socket::shutdown_both, ec_read);

                                    // not_connected happens sometimes so don't bother reporting it.
                                    if(ec_read && ec_read != beast::errc::not_connected) {
                                        ::xcat::ApiCallResponse res;
                                        res.ec = ec_read;
                                        resp(res);
                                        return;
                                    }

                                    ::xcat::ApiCallResponse res;
                                    res.status_code = boost_req->res.result_int();
                                    std::cout << res.status_code << " " << res.body << std::endl;
                                    resp(res);

                                    // If we get here then the connection is closed gracefully

                                }
                            );

                        }
                    );

                }
            );
        }
    );
}

void runHttps(boost::asio::io_context& ioc_, ::xcat::ApiCallRequest req, std::function<void(::xcat::ApiCallResponse)> resp, unsigned int timeout_ms, std::string host, std::string port, boost::asio::ssl::context ctx) {

    // Set up an HTTP GET request message
    auto method = convert_method(req.method);
    if (method == boost::beast::http::verb::unknown) {
        ::xcat::ApiCallResponse res;
        res.ec = cw::error::error_type::invalid_method;
        resp(res);
        return;
    }

    // run batchsystem command asynchronously
    std::shared_ptr<RequestSSL> boost_req{new RequestSSL{boost::asio::ip::tcp::resolver{make_strand(ioc_.get_executor())}, beast::ssl_stream<beast::tcp_stream>{make_strand(ioc_.get_executor()), ctx}, {}, {}, {}}};

    boost_req->req.version(11);
    boost_req->req.method(method);
    boost_req->req.target("https://"+host+"/"+req.uri);
    boost_req->req.set(http::field::host, host);
    boost_req->req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    std::cout << "target " << host+"/"+req.uri << std::endl;

    // Look up the domain name
    boost_req->resolver.async_resolve(
        host,
        port,
        [boost_req, resp, timeout_ms](beast::error_code ec, tcp::resolver::results_type results) {
            if (ec) {
                ::xcat::ApiCallResponse res;
                res.ec = ec;
                resp(res);
                return;
            }

            // Set a timeout on the operation
            beast::get_lowest_layer(boost_req->stream).expires_after(std::chrono::milliseconds(timeout_ms));


            beast::get_lowest_layer(boost_req->stream).async_connect(
                results,
                [boost_req, resp, timeout_ms](beast::error_code ec_connect, tcp::resolver::results_type::endpoint_type) {
                    if (ec_connect) {
                        ::xcat::ApiCallResponse res;
                        res.ec = ec_connect;
                        resp(res);
                        return;
                    }

                    // Set a timeout on the operation
                    beast::get_lowest_layer(boost_req->stream).expires_after(std::chrono::milliseconds(timeout_ms));

                    boost_req->stream.async_handshake(boost::asio::ssl::stream_base::client, [boost_req, timeout_ms, resp](beast::error_code ec_handshake) {
                        if (ec_handshake) {
                            ::xcat::ApiCallResponse res;
                            res.ec = ec_handshake;
                            resp(res);
                            return;
                        }

                        // Send the HTTP request to the remote host
                        http::async_write(boost_req->stream, boost_req->req,
                            [boost_req, resp](beast::error_code ec_write, std::size_t bytes_transferred_read) {
                                boost::ignore_unused(bytes_transferred_read);

                                if (ec_write) {
                                    ::xcat::ApiCallResponse res;
                                    res.ec = ec_write;
                                    resp(res);
                                    return;
                                }

                                // Receive the HTTP response
                                http::async_read(boost_req->stream, boost_req->buffer, boost_req->res,
                                    [boost_req, resp](beast::error_code ec_read, std::size_t bytes_transferred_write) {
                                        boost::ignore_unused(bytes_transferred_write);

                                        if (ec_read) {
                                            ::xcat::ApiCallResponse res;
                                            res.ec = ec_read;
                                            resp(res);
                                            return;
                                        }

                                        // Write the message to standard out
                                        std::cout << boost_req->res << std::endl;

                                        // Gracefully close the socket
                                        beast::get_lowest_layer(boost_req->stream).socket().shutdown(tcp::socket::shutdown_both, ec_read);

                                        // not_connected happens sometimes so don't bother reporting it.
                                        if(ec_read && ec_read != beast::errc::not_connected) {
                                            ::xcat::ApiCallResponse res;
                                            res.ec = ec_read;
                                            resp(res);
                                            return;
                                        }

                                        ::xcat::ApiCallResponse res;
                                        res.status_code = boost_req->res.result_int();
                                        std::cout << res.status_code << " " << res.body << std::endl;
                                        resp(res);

                                        // If we get here then the connection is closed gracefully

                                    });
                            });
                    });
            });
    });
}


}
}
}
