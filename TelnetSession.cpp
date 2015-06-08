#include "TelnetServer.h"
#include "TelnetSession.h"
#include "MeasureManager.h"

namespace ba = boost::asio;
namespace bs = boost::system;
using boost::asio::ip::tcp;


TelnetSession::TelnetSession(MeasureManager *measureManager)
        : socket_(Singleton::ioService),
          refreshTimer(Singleton::ioService, boost::posix_time::seconds(0)),
          measureManager(measureManager) { }

tcp::socket &TelnetSession::socket() { return socket_; }

void TelnetSession::start() {
    refreshTimer.async_wait(boost::bind(&TelnetSession::refreshTimerHandler,
                                        this,
                                        ba::placeholders::error));
}

void TelnetSession::refreshTimerHandler(bs::error_code ec) {
    if (!ec) {
        vector<string> state = measureManager->print();
        string output = "\x1B[2J\x1B[;H";
        for (size_t i = 0; i < min((size_t) 24, state.size()); ++i) {
            output += state[i] + "\n";
        }
        memset(data, 0, sizeof(data));
        sprintf(data, "%s", output.c_str());
        socket_.async_write_some(ba::buffer(data, output.size()),
                                 boost::bind(&TelnetSession::handle_write,
                                             this,
                                             ba::placeholders::error));
        refreshTimer.expires_at(refreshTimer.expires_at() +
                                boost::posix_time::milliseconds((int64_t) (Singleton::vm["v"].as<double>() * 1000)));
        refreshTimer.async_wait(boost::bind(&TelnetSession::refreshTimerHandler,
                                            this,
                                            ba::placeholders::error));
    } else {
//        cerr << ec.message() << endl;
    }
}

void TelnetSession::handle_write(const bs::error_code &error) {
    if (!error) {
    }
    else {
        std::cout << "TelnetSession::handle_write error: " << error.message() << std::endl;
        refreshTimer.cancel();
        delete this;
    }
}

