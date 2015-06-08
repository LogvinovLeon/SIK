//
// Created by root on 05.06.15.
//

#ifndef SIK_OPOZNIENIA_ENDPOINT_H
#define SIK_OPOZNIENIA_ENDPOINT_H


#include <boost/asio.hpp>

class Endpoint {
public:
    Endpoint(const boost::asio::ip::address_v4 &addr, unsigned short port) : addr(addr), port(port) { }

    bool operator<(const Endpoint &a) const {
        return make_pair(addr, port) < make_pair(a.addr, a.port);
    }

    boost::asio::ip::address_v4 addr;
    unsigned short port;
};


#endif //SIK_OPOZNIENIA_ENDPOINT_H
