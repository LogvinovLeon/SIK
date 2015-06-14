//
// Created by root on 05.06.15.
//

#ifndef SIK_OPOZNIENIA_MEASUREMANAGER_H
#define SIK_OPOZNIENIA_MEASUREMANAGER_H

#include <boost/asio.hpp>
#include <boost/date_time.hpp>
#include "Measurer.h"

namespace ba = boost::asio;
using std::vector;
using std::pair;
using tIP=ba::ip::address_v4;

class MeasureManager {
public:
    MeasureManager()
            : measureTimer(Singleton::ioService, boost::posix_time::seconds(0)) {
//        active(tIP::from_string("188.226.190.190"));
//        active(tIP::from_string("216.58.209.35"));
//        active(tIP::from_string("127.0.0.1"));
        measureTimer.async_wait(boost::bind(&MeasureManager::measureTimerHandler,
                                            this,
                                            ba::placeholders::error));
    }

    void measureTimerHandler(boost::system::error_code ec) {
        assert(!ec);
        measure();
        measureTimer.expires_at(measureTimer.expires_at() +
                                boost::posix_time::seconds(Singleton::vm["t"].as<uint16_t>()));
        measureTimer.async_wait(boost::bind(&MeasureManager::measureTimerHandler,
                                            this,
                                            ba::placeholders::error));
    }

    void active(tIP ip) {
        if (!measurers.count(ip)) {
            measurers.emplace(ip, new Measurer(ip));
        }
    }

    void inActive(tIP ip) {
        auto it = measurers.find(ip);
        if (it != measurers.end()) {
            delete it->second;
            measurers.erase(it);
        }
    }

    void measure() {
        for (auto &it : measurers) {
            it.second->measure();
        }
    }

    vector<string> print() {
        vector<pair<Measurer *, tIP>> sorted_measurers;
        for (auto &it : measurers) {
            sorted_measurers.push_back(make_pair(it.second, it.first));
        }
        sort(sorted_measurers.begin(), sorted_measurers.end(),
             [](const pair<Measurer *, tIP> &a, const pair<Measurer *, tIP> &b) {
                 return a.first->getAverageDelay() < b.first->getAverageDelay();
             });
        vector<string> res;
        for (auto &it : sorted_measurers) {
            string addr = it.second.to_string();
            string delays = it.first->printDelays();
            unsigned long spaces_count = (unsigned long)
                                                 max(min((int) (it.first->getAverageDelay() / MICROSEC_PER_SPACE),
                                                         (int) (TERMINAL_WIDTH - addr.size() - delays.size() - 1)),
                                                     0) + 1;
            string spaces;
            for (auto i = 0; i < spaces_count; i++) {
                spaces += " ";
            }
            res.push_back(addr + spaces + delays);
        }
        return res;
    }

private:
    map<tIP, Measurer *> measurers;
    ba::deadline_timer measureTimer;
    const int TERMINAL_WIDTH = 80;
    const int MICROSEC_PER_SPACE = 10000;
};


#endif //SIK_OPOZNIENIA_MEASUREMANAGER_H
