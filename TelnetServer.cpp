#include "TelnetServer.h"
#include "TelnetSession.h"
#include "MeasureManager.h"

namespace ba = boost::asio;
namespace bs = boost::system;
using boost::asio::ip::tcp;

TelnetServer::TelnetServer(MeasureManager *measureManager)
        : acceptor(Singleton::ioService, tcp::endpoint(tcp::v4(), Singleton::vm["U"].as<uint16_t>())),
          measureManager(measureManager) {
    start_accept();
}

void TelnetServer::start_accept() {
    TelnetSession *new_session = new TelnetSession(measureManager);
    acceptor.async_accept(new_session->socket(),
                          boost::bind(&TelnetServer::handle_accept,
                                      this,
                                      new_session,
                                      ba::placeholders::error));
}

void TelnetServer::handle_accept(TelnetSession *new_session, const bs::error_code &error) {
    if (!error) {
        new_session->start();
    }
    else {
//        std::cout << "TelnetServer::handle_accept error: " << error << std::endl;
        delete new_session;
    }
    start_accept();
}