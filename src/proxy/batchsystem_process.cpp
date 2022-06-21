#include "proxy/batchsystem_process.h"

#include <boost/optional.hpp>
#include <boost/process.hpp>

namespace bp = boost::process;

namespace {

struct CmdProcess {
    boost::optional<bp::child> cp;
    boost::optional<bp::async_pipe> pipe_out;
    boost::optional<bp::async_pipe> pipe_err;
};

}

namespace cw {
namespace proxy {
namespace batch {

void runCommand(boost::asio::io_context& ioc_, cw::batch::Result& result, const cw::batch::Cmd& cmd) {
    // run batchsystem command asynchronously
    std::shared_ptr<CmdProcess> process{new CmdProcess{}};
    auto cb = [process, &result](int ret, const std::error_code& ec) {
        result.exit = ec ? -2 : ret; // use -2 to mark error in boost process (failed to start/find command etc.)
    };
    if (cmd.opts & cw::batch::cmdopt::capture_stdout) {
        process->pipe_out.emplace(ioc_);
        boost::asio::async_read(*(process->pipe_out), boost::asio::dynamic_buffer(result.out), [](const boost::system::error_code &, std::size_t){});
    }
    if (cmd.opts & cw::batch::cmdopt::capture_stderr) {
        process->pipe_err.emplace(ioc_);
        boost::asio::async_read(*(process->pipe_err), boost::asio::dynamic_buffer(result.err), [](const boost::system::error_code &, std::size_t){});
    }

    if ((cmd.opts & cw::batch::cmdopt::capture_stdout_stderr) == cw::batch::cmdopt::capture_stdout_stderr) {
        process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > *(process->pipe_out), bp::std_err > *(process->pipe_err), ioc_, bp::on_exit=cb);
    } else if (cmd.opts & cw::batch::cmdopt::capture_stdout) {
        process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > *(process->pipe_out), bp::std_err > bp::null, ioc_, bp::on_exit=cb);
    } else if (cmd.opts & cw::batch::cmdopt::capture_stderr) {
        process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_err > *(process->pipe_err), bp::std_out > bp::null, ioc_, bp::on_exit=cb);
    } else {
        process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > bp::null, bp::std_err > bp::null, ioc_, bp::on_exit=cb);
    }
}

}
}
}

