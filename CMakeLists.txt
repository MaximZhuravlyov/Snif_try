cmake_minimum_required(VERSION 3.10)
project(Sniffer)

set(CMAKE_CXX_STANDARD 11)

#add_library(pcap)
link_libraries(pcap)
add_executable(Sniffer main.cpp net_headers.h network.cpp network.h Printer.cpp Printer.h)

