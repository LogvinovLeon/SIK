//
// Created by leonid on 05.06.15.
//

#ifndef SIK_OPOZNIENIA_UDPMEASURER_H
#define SIK_OPOZNIENIA_UDPMEASURER_H

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "DelayMeasurer.hpp"
#include <iostream>
#include <assert.h>

using boost::asio::ip::udp;
using namespace std;

class UDPMeasurer : public DelayMeasurer<udp> {

public:
    UDPMeasurer(const udp::endpoint &endpoint)
            : DelayMeasurer(endpoint) {
        memset(data, 0, sizeof(data));
    }

    void measure() {
        uint64_t time[1] = {be64toh(getTimeStamp())};
        socket_.async_send_to(boost::asio::buffer(time),
                              endpoint,
                              boost::bind(&UDPMeasurer::sendHandler,
                                          this,
                                          boost::asio::placeholders::error));
    }

private:
    enum {
        max_length = 17
    };
    char data[max_length];
    udp::endpoint sender_endpoint;

    void sendHandler(boost::system::error_code ec) {
        assert(!ec);
        socket_.async_receive_from(boost::asio::buffer(data, max_length),
                                   sender_endpoint,
                                   boost::bind(&UDPMeasurer::receiveHandler,
                                               this,
                                               boost::asio::placeholders::error,
                                               boost::asio::placeholders::bytes_transferred));
    }

    void receiveHandler(boost::system::error_code ec, size_t bytes) {
        assert(bytes == max_length - 1);
        uint64_t time[3];
        memcpy(time, data, max_length - 1);
        time[0] = htobe64(time[0]);
        time[1] = htobe64(time[1]);
        time[2] = getTimeStamp();
        assert(time[0] <= time[2]);
        delays.push_back(time[2] - time[0]);
    }

};


#endif //SIK_OPOZNIENIA_UDPMEASURER_H
