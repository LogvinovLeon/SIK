//
// Created by root on 06.06.15.
//

#ifndef SIK_OPOZNIENIA_UDPSERVER_H
#define SIK_OPOZNIENIA_UDPSERVER_H


#include <boost/asio.hpp>

using namespace boost::asio::ip;

class UDPServer {
public:
    UDPServer();

private:
    void start_receive();

    void handle_receive(const boost::system::error_code &error, std::size_t len);

    void handle_send(const boost::system::error_code &error, std::size_t bytes_transferred);

    enum {
        max_length = 17
    };
    char data[max_length];
    udp::socket socket;
    udp::endpoint endpoint;
};


#endif //SIK_OPOZNIENIA_UDPSERVER_H
