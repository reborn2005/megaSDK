cmake_minimum_required(VERSION 3.10)

# Set project name
project(FileFingerPrint)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include header files
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Define executable and its source files
add_executable(testFingerprint 
    testFingerprint.cpp
    FileFingerprint.cpp
    AESHandler.cpp
    FileCopyDecision.cpp
)

# Link any necessary libraries (none in this case, all is standard C++)
# target_link_libraries(testFingerprint <library_name>)
