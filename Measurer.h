//
// Created by root on 05.06.15.
//

#ifndef SIK_OPOZNIENIA_MEASURER_H
#define SIK_OPOZNIENIA_MEASURER_H


#include "ICMPMeasurer.h"
#include "UDPMeasurer.h"
#include "TCPMeasurer.h"
#include "Endpoint.h"
#include <boost/asio.hpp>

class Measurer {
public:
    Measurer(boost::asio::ip::address_v4 ip)
            : udpMeasurer(new UDPMeasurer(udp::endpoint(ip, Singleton::vm["u"].as<uint16_t>()))),
              tcpMeasurer(new TCPMeasurer(tcp::endpoint(ip, 22))),
              icmpMeasurer(new ICMPMeasurer(icmp::endpoint(ip, 42))) { }

    virtual ~Measurer() {
        delete udpMeasurer;
        delete tcpMeasurer;
        delete icmpMeasurer;
    }

    void measure() {
        udpMeasurer->measure();
        tcpMeasurer->measure();
        icmpMeasurer->measure();
    }

    tuple<double, double, double> getDelays() const {
        return std::tuple<double, double, double>(udpMeasurer->getDelay(),
                                                  tcpMeasurer->getDelay(),
                                                  icmpMeasurer->getDelay());
    }

    string printDelays() const {
        auto d = getDelays();
        stringstream ss;
        ss << get<0>(d) << " " << get<1>(d) << " " << get<2>(d);
        return ss.str();
    }

    double getAverageDelay() const {
        auto d = getDelays();
        double sum = 0;
        double cnt = 0;
        if (get<0>(d) != std::numeric_limits<double>::infinity()) {
            sum += get<0>(d);
            cnt++;
        }
        if (get<1>(d) != std::numeric_limits<double>::infinity()) {
            sum += get<1>(d);
            cnt++;
        }
        if (get<2>(d) != std::numeric_limits<double>::infinity()) {
            sum += get<2>(d);
            cnt++;
        }
        return cnt ? sum / cnt : std::numeric_limits<double>::infinity();
    }

private:
    UDPMeasurer *udpMeasurer;
    TCPMeasurer *tcpMeasurer;
    ICMPMeasurer *icmpMeasurer;
};


#endif //SIK_OPOZNIENIA_MEASURER_H
