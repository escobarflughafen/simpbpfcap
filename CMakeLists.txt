cmake_minimum_required(VERSION 3.13)
project(NetworkSniffer C)

set(CMAKE_C_STANDARD 99)

add_executable(NetworkSniffer main.c display.h display.c sniffer.c sniffer.h analyzer.c analyzer.h)