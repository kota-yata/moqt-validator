// main.cpp
// CLI test driver for MoQT control message validator

#include <moqt/validator.hpp>
#include <iostream>
#include <vector>

int main() {
    using namespace moqt;

    // Test SUBSCRIBE: type=0x03, request_id=5, track_alias=7
    std::vector<uint8_t> msg1 = {0x03, 0x05, 0x07};
    std::cout << validate_control_message(msg1) << std::endl;

    // Test CLIENT_SETUP: type=0x01, 1 version (0x01), param=0x01:"/test"
    std::vector<uint8_t> msg2 = {0x01, 0x01, 0x01, 0x01, 0x05, '/', 't', 'e', 's', 't'};
    std::cout << validate_control_message(msg2) << std::endl;

    // Test SERVER_SETUP: type=0x02, version=0x01, param=0x02:"ok"
    std::vector<uint8_t> msg3 = {0x02, 0x01, 0x02, 0x02, 'o', 'k'};
    std::cout << validate_control_message(msg3) << std::endl;

    return 0;
}
