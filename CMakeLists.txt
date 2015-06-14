cmake_minimum_required(VERSION 2.8)
project(SIK_opoznienia)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wno-sign-compare -Wno-reorder")

set(SOURCE_FILES opoznienia.cpp)

add_executable(SIK_opoznienia ${SOURCE_FILES}
DelayMeasurer.hpp
IPv4Header.hpp
ICMPHeader.hpp
ICMPMeasurer.h
Measurer.h
MeasureManager.h
TelnetServer.h
TelnetServer.cpp
TelnetSession.cpp
Singleton.h
UDPServer.cpp
UDPServer.h
MDNSDiscoverer.cpp
MDNSDiscoverer.h
mdns_header.h)

target_link_libraries(SIK_opoznienia boost_system pthread boost_program_options boost_date_time)