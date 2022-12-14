#include "proxy/batchsystem_process.h"

#include <boost/optional.hpp>
#include <boost/process.hpp>
#include <boost/asio.hpp>
#include <iostream>

namespace bp = boost::process;

namespace {

struct CmdProcess {
    boost::optional<bp::child> cp;
    boost::optional<bp::async_pipe> pipe_out;
    boost::optional<bp::async_pipe> pipe_err;
    boost::optional<boost::asio::deadline_timer> deadline_timer;
    boost::process::group group;
    std::string out;
    std::string err;
    
};

}

namespace cw {
namespace proxy {
namespace batch {

void runCommand(boost::asio::io_context& ioc_, cw::batch::Cmd cmd, std::function<void(cw::batch::Result)> resp, unsigned int timeout_ms) {
    // run batchsystem command asynchronously
    std::shared_ptr<CmdProcess> process{new CmdProcess{}};
    auto cb = [process, resp](int ret, const std::error_code& ec) {
        if (process->deadline_timer.has_value()) process->deadline_timer->cancel();
        cw::batch::Result res;
        res.ec = ec;
        res.exit = ec ? cmd_status_spawn_failed : ret; // use to mark error in boost process (failed to start/find command etc.)
        res.out = std::move(process->out);
        res.err = std::move(process->err);
        resp(res);
    };
    if (cmd.opts & cw::batch::cmdopt::capture_stdout) {
        process->pipe_out.emplace(ioc_);
        boost::asio::async_read(*(process->pipe_out), boost::asio::dynamic_buffer(process->out), [](const boost::system::error_code &, std::size_t){});
    }
    if (cmd.opts & cw::batch::cmdopt::capture_stderr) {
        process->pipe_err.emplace(ioc_);
        boost::asio::async_read(*(process->pipe_err), boost::asio::dynamic_buffer(process->err), [](const boost::system::error_code &, std::size_t){});
    }

    try {
        if ((cmd.opts & cw::batch::cmdopt::capture_stdout_stderr) == cw::batch::cmdopt::capture_stdout_stderr) {
            process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > *(process->pipe_out), bp::std_err > *(process->pipe_err), ioc_, process->group, bp::on_exit=cb);
        } else if (cmd.opts & cw::batch::cmdopt::capture_stdout) {
            process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > *(process->pipe_out), bp::std_err > bp::null, ioc_, process->group, bp::on_exit=cb);
        } else if (cmd.opts & cw::batch::cmdopt::capture_stderr) {
            process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_err > *(process->pipe_err), bp::std_out > bp::null, ioc_, process->group, bp::on_exit=cb);
        } else {
            process->cp.emplace(bp::search_path(cmd.cmd), bp::args(cmd.args), bp::std_out > bp::null, bp::std_err > bp::null, ioc_, process->group, bp::on_exit=cb);
        }
    } catch (const bp::process_error& e) {
        cw::batch::Result res;
        res.ec = e.code();
        resp(res);
        return;
    }

    // has to be after process::child construction with process->cp.emplace
    // because that can throw an boost::process::process_error and deadline_timer would not have been cancelled and would trigger error on kill otherwise
    if (timeout_ms != 0) {
        process->deadline_timer.emplace(ioc_);
        process->deadline_timer->expires_from_now(boost::posix_time::milliseconds(timeout_ms));
        process->deadline_timer->async_wait([process](boost::system::error_code ec){
            if (ec == boost::asio::error::operation_aborted) return;
            process->group.terminate();
        });
    }

}

}
}
}
