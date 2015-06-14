#include "MDNSDiscoverer.h"
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time.hpp>
#include <ifaddrs.h>

MDNSDiscoverer::MDNSDiscoverer(MeasureManager *measureManager)
        : state(CHECKING),
          id(0),
          check_name_query_timer(Singleton::ioService, QUERY_EXPIRE_TIME),
          network_discover_timer(Singleton::ioService, boost::posix_time::seconds(Singleton::vm["T"].as<uint>())),
          ttl_checker(Singleton::ioService, boost::posix_time::seconds(1)),
          measureManager(measureManager),
          socket_(Singleton::ioService),
          endpoint(MULTICAST_ADDRESS, MULTICAST_PORT) {
    getIP();
    udp::endpoint listen_endpoint(LISTEN_ADDRESS, MULTICAST_PORT);
    socket_.open(listen_endpoint.protocol());
    socket_.set_option(udp::socket::reuse_address(true));
    socket_.bind(listen_endpoint);
    socket_.set_option(multicast::join_group(MULTICAST_ADDRESS));
    check_name_query_timer.async_wait(boost::bind(&MDNSDiscoverer::query_expiration_handler,
                                                  this,
                                                  boost::asio::placeholders::error));
    network_discover_timer.async_wait(boost::bind(&MDNSDiscoverer::time_to_check_handler,
                                                  this,
                                                  boost::asio::placeholders::error));
    ttl_checker.async_wait(boost::bind(&MDNSDiscoverer::ttl_check_handler,
                                       this,
                                       boost::asio::placeholders::error));
    mdns_package mdnsPackage(mdns_header(mdns_header::query));
    mdnsPackage.addQuery(mdns_query(OPOZNIENIA, mdns_reply::QTYPE_PTR));
    send(mdnsPackage);
    receive();
}

void MDNSDiscoverer::receive() {
    response_buf.consume(response_buf.size());
    socket_.async_receive_from(response_buf.prepare(max_length),
                               sender_endpoint,
                               boost::bind(&MDNSDiscoverer::receive_handler,
                                           this,
                                           boost::asio::placeholders::error,
                                           boost::asio::placeholders::bytes_transferred));
}

void MDNSDiscoverer::receive_handler(const boost::system::error_code &error, size_t bytes_recvd) {
    if (!error) {
        if (sender_endpoint.port() != MULTICAST_PORT) {
            cerr << "PORT: " << sender_endpoint.port() << endl;
            return;
        }
        if (bytes_recvd < 12) {
            cerr << "<12 bytes" << endl;
            return;
        }
        try {
            response_buf.commit(bytes_recvd);
            std::istream is(&response_buf);
            mdns_package package;
            is >> package;
            cout << package.toString() << endl;
            process(package);
        } catch (const char *e) {
            cerr << e << endl;
        } catch (const std::out_of_range &oor) {
            cerr << oor.what() << endl;
        }
        receive();
    } else {
        cerr << error.message() << endl;
    }

}

void MDNSDiscoverer::process(const mdns_package &package) {
    if (state == CHECKING) {
        for (auto rep: package.getReplies()) {
            set<string> names;
            if ((rep.getQtype() == mdns_reply::QTYPE_PTR) && (rep.getDomain() == OPOZNIENIA)) {
                mdns_domain possible_collision(rep.getRdata());
                names.insert(possible_collision.getName());

            }
            while (names.count(currentName())) ++id;
            nameChoosen();
        }
    } else {
        respond(package);
        consume_responses(package);
    }
}

void MDNSDiscoverer::respond(const mdns_package &package) {
    cout << "START_REPLY" << endl;
    mdns_package mdnsPackage(mdns_header(mdns_header::response_authoritative));
    for (auto que: package.getQueries()) {
        auto domain = que.getDomain();
        if (domain.getType() == "_opoznienia" && domain.getProtocol() == "_udp") {
            if (que.getQtype() == mdns_reply::QTYPE_PTR) {
                cout << "reply_ptr" << endl;
                mdnsPackage.addReply(mdns_reply(OPOZNIENIA, mdns_reply::QTYPE_PTR,
                                                Singleton::vm["T"].as<uint>() * 3,
                                                {currentName(), "_opoznienia", "_udp", "local"}));
            }
            if (que.getQtype() == mdns_reply::QTYPE_A) {
                cout << "reply_a" << endl;
                cout << "RESPOND_IP " << IP.to_string() << endl;
                mdnsPackage.addReply(mdns_reply({currentName(), "_opoznienia", "_udp", "local"}, mdns_reply::QTYPE_A,
                                     Singleton::vm["T"].as<uint>() * 3, IP));
            }
        }
        if (Singleton::vm["s"].as<bool>()) {
            if (domain.getType() == "_ssh" && domain.getProtocol() == "_tcp") {
                if (que.getQtype() == mdns_reply::QTYPE_PTR) {
                    cout << "reply_ptr" << endl;
                    mdnsPackage.addReply(mdns_reply(SSH, mdns_reply::QTYPE_PTR,
                                                    Singleton::vm["T"].as<uint>() * 3,
                                                    {currentName(), "_ssh", "_tcp", "local"}));
                }
                if (que.getQtype() == mdns_reply::QTYPE_A) {
                    cout << "reply_a" << endl;
                    mdnsPackage.addReply(mdns_reply({currentName(), "_ssh", "_tcp", "local"}, mdns_reply::QTYPE_A,
                                         Singleton::vm["T"].as<uint>() * 3, IP));
                }
            }
        }
    }
    if (mdnsPackage.getReplies().size()) {
        cout << "RESPONDING: " << mdnsPackage.toString() << endl;
        send(mdnsPackage);
    }
}

void MDNSDiscoverer::consume_responses(const mdns_package &package) {
    for (auto rep: package.getReplies()) {
        auto domain = rep.getDomain();
        if ((domain.getType() == "_opoznienia" && domain.getProtocol() == "_udp") ||
            (domain.getType() == "_ssh" && domain.getProtocol() == "_tcp")) {
            if (rep.getQtype() == mdns_reply::QTYPE_PTR) {
                map<mdns_domain, boost::posix_time::ptime>::iterator it;
                it = PTRrecords.find(rep.getPTRData());
                if (it != PTRrecords.end()) {
                    PTRrecords[it->first] = boost::posix_time::microsec_clock::universal_time() +
                                            boost::posix_time::seconds(rep.getTtl());
                } else {
                    PTRrecords[rep.getPTRData()] = boost::posix_time::microsec_clock::universal_time() +
                                                   boost::posix_time::seconds(rep.getTtl());
                }
            }
            if (rep.getQtype() == mdns_reply::QTYPE_A) {
                cout << "NEW_IP " << rep.getIP().to_string() << endl;
                Arecords[rep.getDomain()] = make_pair(rep.getIP(),
                                                      boost::posix_time::microsec_clock::universal_time() +
                                                      boost::posix_time::seconds(rep.getTtl()));
            }
        }
    }
    mdns_package mdnsPackage(mdns_header(mdns_header::query));
    for (auto it: PTRrecords) {
        if (it.second > boost::posix_time::microsec_clock::universal_time()) {
            std::map<mdns_domain, std::pair<ba::ip::address_v4, boost::posix_time::ptime>>
            ::iterator
                    i;
            i = Arecords.find(it.first);
            if (i == Arecords.end()) {
                mdnsPackage.addQuery(mdns_query(it.first, mdns_query::QTYPE_A));
            } else if (i->second.second <= boost::posix_time::microsec_clock::universal_time()) {
                mdnsPackage.addQuery(mdns_query(i->first, mdns_query::QTYPE_A));
            }
        }
    }
    if (mdnsPackage.getQueries().size()) {
        send(mdnsPackage);
    }
}

void MDNSDiscoverer::send(mdns_package mdnsPackage) {
    std::ostringstream os;
    os << mdnsPackage;
    message_ = os.str();
    socket_.async_send_to(boost::asio::buffer(message_),
                          endpoint,
                          boost::bind(&MDNSDiscoverer::send_handler,
                                      this,
                                      boost::asio::placeholders::error,
                                      boost::asio::placeholders::bytes_transferred));
}

void MDNSDiscoverer::send_handler(const boost::system::error_code &error, size_t bytes_recvd) {
    if (error) {
        cerr << error << " " << error.message() << endl;
    }
}

void MDNSDiscoverer::getIP() {
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmpAddrPtr = NULL;
    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if ((strcmp(ifa->ifa_name, "ppp0") == 0) ||
                    (strcmp(ifa->ifa_name, "eth0") == 0) ||
                    (strcmp(ifa->ifa_name, "wlan0") == 0)) {
                    tmpAddrPtr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
                    char addressBuffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                    printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
                    IP = boost::asio::ip::address_v4::from_string(addressBuffer);
                    cout << IP.to_string() << endl;
                }
            }
        }
    }
    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);
}

void MDNSDiscoverer::query_expiration_handler(const boost::system::error_code &error) {
    if (!error) {
        nameChoosen();
    } else {
        if (error != boost::asio::error::operation_aborted)
            std::cerr << error.message() << std::endl;
    }
}

void MDNSDiscoverer::time_to_check_handler(const boost::system::error_code &error) {
    if (!error) {
        mdns_package mdnsPackage(mdns_header(mdns_header::query));
        mdnsPackage.addQuery(mdns_query(OPOZNIENIA, mdns_query::QTYPE_PTR));
        mdnsPackage.addQuery(mdns_query(SSH, mdns_query::QTYPE_PTR));
        send(mdnsPackage);
        network_discover_timer.expires_from_now(boost::posix_time::seconds(Singleton::vm["T"].as<uint>()));
        network_discover_timer.async_wait(boost::bind(&MDNSDiscoverer::time_to_check_handler,
                                                      this,
                                                      boost::asio::placeholders::error));
    } else {
        std::cerr << error.message() << std::endl;
    }
}

void MDNSDiscoverer::nameChoosen() {
    state = STABLE;
    cout << currentName() << endl;
    check_name_query_timer.cancel();
}

void MDNSDiscoverer::ttl_check_handler(const boost::system::error_code &error) {
    if (!error) {
        for (auto it: Arecords) {
            if (it.second.second > boost::posix_time::microsec_clock::universal_time()) {
                measureManager->active(it.second.first);
            } else {
                measureManager->inActive(it.second.first);
            }
        }
        ttl_checker.expires_from_now(boost::posix_time::seconds(1));
        ttl_checker.async_wait(boost::bind(&MDNSDiscoverer::ttl_check_handler,
                                           this,
                                           boost::asio::placeholders::error));
    } else {
        cout << error.message() << endl;
    }
}
