//
// Created by leonid on 05.06.15.
//

#ifndef SIK_OPOZNIENIA_ICMPMEASURER_H
#define SIK_OPOZNIENIA_ICMPMEASURER_H


#include "DelayMeasurer.hpp"
#include "IPv4Header.hpp"
#include "ICMPHeader.hpp"
#include "Singleton.h"

using boost::asio::ip::icmp;
using namespace boost;

class ICMPMeasurer : public DelayMeasurer<icmp> {
public:
    ICMPMeasurer(const icmp::endpoint &endpoint)
            : DelayMeasurer(endpoint), sequence_number(0) {
        startReceive();
    }

private:
public:
    virtual void measure() {
        char body[4] = {0b00110100, 0b01010011, 0b01110100, 0b00000100};
        ICMPHeader echo_request;
        echo_request.type(ICMPHeader::echo_request);
        echo_request.code(0);
        echo_request.identifier(get_identifier());
        echo_request.sequence_number(sequence_number = ++Singleton::sequence_number);
        compute_checksum(echo_request, body, body + 4);
        request_buffer.consume(request_buffer.size());
        std::ostream os(&request_buffer);
        os << echo_request << body;
        time_sent = getTime();
        socket_.async_send_to(request_buffer.data(),
                              endpoint,
                              boost::bind(&ICMPMeasurer::sendHandler,
                                          this,
                                          boost::asio::placeholders::error));
    }

    void sendHandler(boost::system::error_code ec) {
        if (!ec) {

        } else {
            cerr << ec.message() << endl;
        }
    }

    void startReceive() {
        reply_buffer.consume(reply_buffer.size());
        socket_.async_receive(reply_buffer.prepare(65536),
                              boost::bind(&ICMPMeasurer::handle_receive,
                                          this,
                                          boost::asio::placeholders::bytes_transferred));
    }

    void handle_receive(std::size_t length) {
        if (length) {
            reply_buffer.commit(length);
            std::istream is(&reply_buffer);
            IPv4Header ipv4_hdr;
            ICMPHeader icmp_hdr;
            is >> ipv4_hdr >> icmp_hdr;
            if (is && icmp_hdr.type() == ICMPHeader::echo_reply
                && icmp_hdr.identifier() == get_identifier()
                && icmp_hdr.sequence_number() == sequence_number) {
                posix_time::ptime now = getTime();
                delays.push_back((now - time_sent).total_microseconds());
            }
        }
        startReceive();
    }

    static unsigned short get_identifier() {
        return 0x13;
    }

    unsigned short sequence_number;
    posix_time::ptime time_sent;
    boost::asio::streambuf reply_buffer;
    boost::asio::streambuf request_buffer;
};


#endif //SIK_OPOZNIENIA_ICMPMEASURER_H