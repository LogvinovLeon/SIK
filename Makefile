CC=g++
CFLAGS=-std=c++11 -O2
LDFLAGS=-lboost_system -lboost_program_options -lboost_date_time
SOURCES=opoznienia.cpp MDNSDiscoverer.cpp TelnetServer.cpp TelnetSession.cpp UDPServer.cpp
EXECUTABLE=opoznienia

all: opoznienia

opoznienia:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE) $(LDFLAGS)


