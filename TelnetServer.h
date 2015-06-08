#ifndef __TELNET_SERVER_HPP__
#define __TELNET_SERVER_HPP__

#include <stdint.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include "MeasureManager.h"
#include "TelnetSession.h"

namespace ba = boost::asio;
namespace bs = boost::system;
using boost::asio::ip::tcp;

class TelnetServer {
public:
    TelnetServer(MeasureManager *measureManager);

private:
    void start_accept();

    void handle_accept(TelnetSession *new_session, const bs::error_code &error);

    MeasureManager *measureManager;
    tcp::acceptor acceptor;
};

#endif
