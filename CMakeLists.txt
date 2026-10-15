# ESP32 Network Shield — root CMake file (CONTRACTS.md §9).
# Build with ESP-IDF v5.1+: `idf.py build` (IDF_PATH must be set).
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32-network-shield)
