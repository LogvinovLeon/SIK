#ifndef SIK_OPOZNIENIA_MDNSDISCOVERER_H
#define SIK_OPOZNIENIA_MDNSDISCOVERER_H


#include <boost/asio.hpp>
#include "Singleton.h"
#include "mdns_header.h"
#include "MeasureManager.h"
#include <iostream>

using namespace boost::asio::ip;
using namespace std;

const address_v4 LISTEN_ADDRESS = address_v4::from_string("0.0.0.0");
const address_v4 MULTICAST_ADDRESS = address_v4::from_string("224.0.0.251");
const uint16_t MULTICAST_PORT = 5353;
const boost::posix_time::seconds QUERY_EXPIRE_TIME = boost::posix_time::seconds(1);
const std::initializer_list<string> OPOZNIENIA = {"_opoznienia", "_udp", "local"};
const std::initializer_list<string> SSH = {"_ssh", "_tcp", "local"};

class MDNSDiscoverer {
public:
    MDNSDiscoverer(MeasureManager *measureManager);

    void receive();

    void receive_handler(const boost::system::error_code &error, size_t bytes_recvd);

    void process(const mdns_package &package);

    void respond(const mdns_package &package);

    void consume_responses(const mdns_package &package);

    void send(mdns_package mdnsPackage);

    void send_handler(const boost::system::error_code &error, size_t bytes_recvd);

    void time_to_check_handler(const boost::system::error_code &error);

    void query_expiration_handler(const boost::system::error_code &error);

    void ttl_check_handler(const boost::system::error_code &error);

    void getIP();

    void nameChoosen();

    string currentName() {
        stringstream ss;
        ss << "_leonid_logvinov_" << (int) id;
        return ss.str();
    }

private:
    enum {
        CHECKING = 0x01,
        STABLE = 0x02
    };
    unsigned char state;
    unsigned char id = 0;
    boost::asio::deadline_timer check_name_query_timer;
    boost::asio::deadline_timer network_discover_timer;
    boost::asio::deadline_timer ttl_checker;
    map<mdns_domain, pair<ba::ip::address_v4, boost::posix_time::ptime>> Arecords;
    map<mdns_domain, boost::posix_time::ptime> PTRrecords;
    ba::ip::address_v4 IP;
    MeasureManager *measureManager;
    udp::socket socket_;
    udp::endpoint sender_endpoint;
    udp::endpoint endpoint;
    boost::asio::streambuf response_buf;
    string message_;
    enum {
        max_length = 65536
    };
};


#endif //SIK_OPOZNIENIA_MDNSDISCOVERER_H
