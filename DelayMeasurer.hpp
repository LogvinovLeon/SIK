//
// Created by leonid on 04.06.15.
//

#ifndef SIK_OPOZNIENIA_DELAYMEASURER_H
#define SIK_OPOZNIENIA_DELAYMEASURER_H

#include <vector>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "Singleton.h"

using namespace std;

template<class Protocol>
class DelayMeasurer {
public:
    DelayMeasurer(const typename Protocol::endpoint &endpoint)
            : endpoint(endpoint), socket_(Singleton::ioService, Protocol::v4()) { }

    virtual ~DelayMeasurer() { }

    virtual void measure() = 0;

    double getDelay() {
        double sum = 0;
        int cnt = 0;
        for (auto delay = delays.rbegin(); delay != delays.rend() && cnt < 10; delay++, cnt++) {
            sum += *delay;
        }
//        for (auto delay : delays) {
//            cout << delay << " ";
//        }
//        cout << endl;
        return cnt ? sum / cnt : std::numeric_limits<double>::infinity();
    }

    static uint64_t getTimeStamp() {
        boost::posix_time::ptime epoch(boost::gregorian::date(1970, 1, 1));
        return (uint64_t) (boost::posix_time::microsec_clock::universal_time() - epoch).total_microseconds();
    }

    static boost::posix_time::ptime getTime() {
        return boost::posix_time::microsec_clock::universal_time();
    }

protected:

    vector<double> delays;
    typename Protocol::socket socket_;
    typename Protocol::endpoint endpoint;
};


#endif //SIK_OPOZNIENIA_DELAYMEASURER_H
