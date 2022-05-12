/**
 * @file main.cpp
 * @brief CLI
 *
 ***********************************************/

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "clipp.h"
#include "utils.h"

#include "batchsystem/batchsystem.h"
#include "batchsystem/factory.h"

#include <reproc++/run.hpp>


#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using boost::asio::ip::tcp;

namespace batch = cw::batch;

bool canceled(false);

/**
 * @brief Handle caught signal
 *
 * This function is called when SIGINT is caught.
 *
 * @param signal Number of signal
 */
void sigHandler(int signal) {
    std::cout << "Caught signal " << signal << std::endl;

    // only exit on second SIGINT
    if (canceled) {
        exit(EXIT_FAILURE);
    }
    canceled = true;
}

class session : public std::enable_shared_from_this<session>
{
public:
  session(tcp::socket socket, boost::asio::ssl::context& context)
    : socket_(std::move(socket), context)
  {
  }

  void start()
  {
    do_handshake();
  }

private:
  void do_handshake()
  {
    auto self(shared_from_this());
    socket_.async_handshake(boost::asio::ssl::stream_base::server, 
        [this, self](const boost::system::error_code& error)
        {
          if (!error)
          {
            do_read();
          }
        });
  }

  void do_read()
  {
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_),
        [this, self](const boost::system::error_code& ec, std::size_t length)
        {
          if (!ec)
          {
            do_write(length);
          }
        });
  }

  void do_write(std::size_t length)
  {
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(data_, length),
        [this, self](const boost::system::error_code& ec,
          std::size_t /*length*/)
        {
          if (!ec)
          {
            do_read();
          }
        });
  }

  boost::asio::ssl::stream<tcp::socket> socket_;
  char data_[1024];
};

class server
{
public:
  server(boost::asio::io_context& io_context, unsigned short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
      context_(boost::asio::ssl::context::sslv23)
  {
    context_.set_options(
        boost::asio::ssl::context::default_workarounds
        | boost::asio::ssl::context::no_sslv2
        | boost::asio::ssl::context::single_dh_use);
    context_.set_password_callback(std::bind(&server::get_password, this));
    context_.use_certificate_chain_file("server.pem");
    context_.use_private_key_file("server.pem", boost::asio::ssl::context::pem);
    context_.use_tmp_dh_file("dh2048.pem");

    do_accept();
  }

private:
  std::string get_password() const
  {
    return "test";
  }

  void do_accept()
  {
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, tcp::socket socket)
        {
          if (!error)
          {
            std::make_shared<session>(std::move(socket), context_)->start();
          }

          do_accept();
        });
  }

  tcp::acceptor acceptor_;
  boost::asio::ssl::context context_;
};


int runCommand(std::string& out, const cw::batch::CmdOptions& opts) {
        std::vector<std::string> args{opts.cmd};
        for (const auto& a: opts.args) args.push_back(a);

        reproc::process process;
        std::error_code ec_start = process.start(args);
        if (ec_start) return -1;

        reproc::sink::string sink(out);
        std::error_code ec_drain = reproc::drain(process, sink, reproc::sink::null);
        if (ec_drain) return -1;

        auto ret = process.wait(reproc::infinite);
        if (ret.second) return -1;

        return ret.first;
}

int main(int argc, char **argv) {
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = sigHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL); /* for CTRL+C */


    bool help = false;

    enum class mode { run,
    };

    mode selected;
    batch::System batchSystem; 

    std::string loginPath = "",
                nodes = "",
                state = "",
                jobs = "",
                queues = "",
                reason = "",
                images = "",
                image = "",
                prescripts = "",
                postbootscripts = "",
                postscripts = "",
                provmethod = "";

    auto generalOpts = (clipp::option("-h", "--help").set(help) % "Shows this help message",
                        (clipp::option("-b", "--batch") & (clipp::required("slurm").set(batchSystem, batch::System::Slurm) | clipp::required("pbs").set(batchSystem, batch::System::Pbs) | clipp::required("lsf").set(batchSystem, batch::System::Lsf))) % "Batch System",
                        (clipp::option("-l", "--loginFile") & clipp::value("path", loginPath)) % "Path for login data"
    );

    auto nodesOpt = (clipp::command("run").set(selected, mode::run)) % "Run server";
    auto cli = ("COMMANDS\n" % (nodesOpt), "OPTIONS\n" % generalOpts);

    if (!clipp::parse(argc, argv, cli) || help) {
        // std::cout << make_man_page(cli, argv[0]) << std::endl;
        std::cout << "USAGE:\n"
                  << clipp::usage_lines(cli, argv[0]) << "\n\n\n"
                  << "PARAMETERS:\n\n"
                  << clipp::documentation(cli) << std::endl;
        return 1;
    }

    batch::BatchSystem batch;
    create_batch(batch, batchSystem, runCommand);

    boost::asio::io_context io_context;
    server s(io_context, atoi(argv[1]));
    io_context.run();

    return 0;
}
