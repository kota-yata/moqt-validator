// test_validator.cpp
// Unit tests for MoQT control message validator

#include <moqt/validator.hpp>
#include <cassert>
#include <iostream>
#include <vector>

using namespace moqt;

void test_subscribe() {
    std::vector<uint8_t> msg = {0x03, 0x05, 0x07};
    std::string result = validate_control_message(msg);
    assert(result.find("SUBSCRIBE") != std::string::npos);
    std::cout << "test_subscribe passed\n";
}

void test_client_setup() {
    std::vector<uint8_t> msg = {0x01, 0x01, 0x01, 0x01, 0x05, '/', 't', 'e', 's', 't'};
    std::string result = validate_control_message(msg);
    assert(result.find("CLIENT_SETUP") != std::string::npos);
    std::cout << "test_client_setup passed\n";
}

void test_server_setup() {
    std::vector<uint8_t> msg = {0x02, 0x01, 0x02, 0x02, 'o', 'k'};
    std::string result = validate_control_message(msg);
    assert(result.find("SERVER_SETUP") != std::string::npos);
    std::cout << "test_server_setup passed\n";
}

void test_empty_message() {
    std::vector<uint8_t> msg = {};
    std::string result = validate_control_message(msg);
    assert(result == "Empty control message");
    std::cout << "test_empty_message passed\n";
}

int main() {
    test_subscribe();
    test_client_setup();
    test_server_setup();
    test_empty_message();
    std::cout << "All tests passed.\n";
    return 0;
}
