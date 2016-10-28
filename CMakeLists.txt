
project(zc)

cmake_minimum_required(VERSION 3.6)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

set(Boost_INCLUDE_DIR /usr/include)
set(Boost_LIBRARY_DIR /usr/lib/)

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
add_executable(zc main.cpp main.h)
target_link_libraries( zc sodium pthread boost_system boost_log_setup boost_log)

