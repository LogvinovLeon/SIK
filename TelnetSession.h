#ifndef __TELNET_SESSION_HPP__
#define __TELNET_SESSION_HPP__

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "MeasureManager.h"

namespace ba = boost::asio;
namespace bs = boost::system;
using boost::asio::ip::tcp;

class TelnetSession {
public:
    TelnetSession(MeasureManager *measureManager);

    virtual ~TelnetSession() { }

    tcp::socket &socket();

    void start();

    enum {
        max_length = 10000
    };

private:
    void refreshTimerHandler(bs::error_code ec);

    void handle_write(const bs::error_code &error);

    ba::deadline_timer refreshTimer;
    MeasureManager *measureManager;
    tcp::socket socket_;
    char data[max_length];
};

#endif
