cmake_minimum_required(VERSION 3.10)
project(secure_network_messaging_crypto_lib)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(prebuilt/libsodium/include)

find_package(JNI REQUIRED)
include_directories(${JNI_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)

add_library(crypto_lib STATIC
        src/NegotiatedCryptoNative.cpp
        src/LengthMessageCrypto.cpp)

ADD_LIBRARY(sodium STATIC IMPORTED)
SET_TARGET_PROPERTIES(sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/prebuilt/libsodium/lib/libsodium.a)
TARGET_LINK_LIBRARIES(crypto_lib sodium)

# jni binding
add_library(crypto_jni SHARED
        src/jni_binding.cpp
        src/LengthMessageCrypto.cpp
        src/NegotiatedCryptoNative.cpp)
target_link_libraries(crypto_jni PRIVATE sodium)

# main executable
add_executable(main src/main.cpp)

target_link_libraries(main crypto_lib)

# google test
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
        crypto_lib_test
        tests/crypto_lib_test.cpp
)
target_link_libraries(
        crypto_lib_test
        GTest::gtest_main
        crypto_lib
)

include(GoogleTest)
gtest_discover_tests(crypto_lib_test)

