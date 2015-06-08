//
// Created by leonid on 04.06.15.
//

#ifndef SIK_OPOZNIENIA_TCPMEASURER_H
#define SIK_OPOZNIENIA_TCPMEASURER_H

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include <assert.h>
#include "DelayMeasurer.hpp"

using boost::asio::ip::tcp;

class TCPMeasurer : public DelayMeasurer<tcp> {
public:
    TCPMeasurer(const tcp::endpoint &endpoint)
            : DelayMeasurer(endpoint) { }

    void measure() {
        socket_.close();
        socket_.async_connect(endpoint,
                              boost::bind(&TCPMeasurer::handleConnect,
                                          this,
                                          boost::asio::placeholders::error,
                                          getTime())
        );
    }

private:
    void handleConnect(const boost::system::error_code &ec, boost::posix_time::ptime start) {
        if (!ec) {
            delays.push_back((getTime() - start).total_microseconds());
        } else {
//            cerr << ec.message() << endl;
        }
        socket_.close();
    }
};


#endif //SIK_OPOZNIENIA_TCPMEASURER_H
