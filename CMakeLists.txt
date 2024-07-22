# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("CMakeProject1")

# Add vcpkg toolchain file if vcpkg is used
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
endif()


# Add source to this project's executable.
add_executable (CMakeProject1 "main.cpp" "main.h" "antivirus.cpp" "antivirus.h")

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Link the OpenSSL library
target_link_libraries(CMakeProject1 PRIVATE OpenSSL::SSL)
target_link_libraries(CMakeProject1 PRIVATE OpenSSL::Crypto)


if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET CMakeProject1 PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
