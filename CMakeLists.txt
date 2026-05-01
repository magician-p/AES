cmake_minimum_required(VERSION 3.31)
project(AES)

set(CMAKE_CXX_STANDARD 20)

add_executable(AES main.cpp
        AES.h
        AES.cpp)
