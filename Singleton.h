//
// Created by root on 06.06.15.
//

#ifndef SIK_OPOZNIENIA_SEQUENCENUMBERSINGLETON_H
#define SIK_OPOZNIENIA_SEQUENCENUMBERSINGLETON_H

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

class Singleton {
public:

    static unsigned short sequence_number;
    static boost::program_options::variables_map vm;
    static boost::asio::io_service ioService;
};


#endif //SIK_OPOZNIENIA_SEQUENCENUMBERSINGLETON_H
