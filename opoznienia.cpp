#include "MeasureManager.h"
#include "TelnetServer.h"
#include "UDPServer.h"
#include "MDNSDiscoverer.h"
#include <boost/program_options.hpp>

namespace po=boost::program_options;
unsigned short Singleton::sequence_number = 0;

boost::asio::io_service Singleton::ioService;

po::variables_map Singleton::vm;

void init_options(int argc, const char *argv[]);

int main(int argc, const char *argv[]) {
    init_options(argc, argv);
    UDPServer udpServer;
    MeasureManager measureManager;
    TelnetServer telnetServer(&measureManager);
    MDNSDiscoverer mdnsDiscoverer(&measureManager);
    Singleton::ioService.run();
    return 0;
}

void init_options(int argc, const char *argv[]) {
    po::options_description desc("Dozwlone opcje");
    desc.add_options()
            ("help", "produce help message")
            ("t", po::value<uint16_t>()->default_value(1), "czas pomiędzy pomiarami opóźnień")
            ("T", po::value<uint>()->default_value(10), "czas pomiędzy wykrywaniem komputerów")
            ("u", po::value<uint16_t>()->default_value(3382), "port serwera do pomiaru opóźnień przez UDP")
            ("s", po::value<bool>()->default_value(false), "rozgłaszanie dostępu do usługi _ssh._tcp")
            ("U", po::value<uint16_t>()->default_value(3637), "port serwera do połączeń z interfejsem użytkownika")
            ("v", po::value<double>()->default_value(1.0), "czas pomiędzy aktualizacjami interfejsu użytkownika");
    po::store(po::command_line_parser(argc, argv).options(desc)
                      .style(po::command_line_style::default_style | po::command_line_style::allow_long_disguise)
                      .run(), Singleton::vm);
    po::notify(Singleton::vm);
    if (Singleton::vm.count("help")) {
        cout << desc << "\n";
        exit(1);
    }
}
