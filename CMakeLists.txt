cmake_minimum_required(VERSION 3.16)

project(CrcLibrary)

add_library(crc INTERFACE)
target_include_directories(crc INTERFACE incl)