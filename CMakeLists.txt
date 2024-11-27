cmake_minimum_required(VERSION 3.10)
project(IERG_4180_Project4 VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Append Conda's directory to CMake's search path
list(APPEND CMAKE_PREFIX_PATH "/root/miniconda3")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Update executable targets
add_executable(netprobserver netprobserver.cpp helper.cpp threadpool.cpp)
add_executable(netprobclient netprobclient.cpp helper.cpp)

# Specify include directories
target_include_directories(netprobserver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(netprobclient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link libraries
target_link_libraries(netprobserver PRIVATE pthread OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(netprobclient PRIVATE pthread OpenSSL::SSL OpenSSL::Crypto)