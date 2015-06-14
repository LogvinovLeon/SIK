//
// Created by root on 06.06.15.
//

#include "UDPServer.h"
#include "Singleton.h"
#include "DelayMeasurer.hpp"
#include <boost/bind.hpp>

using namespace std;

UDPServer::UDPServer()
        : socket(Singleton::ioService, udp::endpoint(udp::v4(), Singleton::vm["u"].as<uint16_t>())) {
    start_receive();
}

void UDPServer::start_receive() {
    socket.async_receive_from(boost::asio::buffer(data, 8),
                              endpoint,
                              boost::bind(&UDPServer::handle_receive,
                                          this,
                                          boost::asio::placeholders::error,
                                          boost::asio::placeholders::bytes_transferred));
}

void UDPServer::handle_receive(const boost::system::error_code &error, size_t len) {
    if (!error) {
        assert(len == 8);
        uint64_t time[2];
        memcpy(time, data, 8);
        time[1] = htobe64(DelayMeasurer<boost::asio::ip::udp>::getTimeStamp());
        memcpy(data, time, 16);
        socket.async_send_to(boost::asio::buffer(data, 16),
                             endpoint,
                             boost::bind(&UDPServer::handle_send,
                                         this,
                                         boost::asio::placeholders::error,
                                         boost::asio::placeholders::bytes_transferred));
        start_receive();
    } else {
        cerr << error.message() << endl;
    }
}

void UDPServer::handle_send(const boost::system::error_code &error, std::size_t bytes_transferred) {
}
