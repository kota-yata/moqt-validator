// validator.cpp
// Entry point for validating MoQT control messages

#include <moqt/validator.hpp>
#include <moqt/control_parser.hpp>

namespace moqt {

std::string validate_control_message(const std::vector<uint8_t>& data) {
    if (data.empty()) return "Empty control message";
    uint8_t type = data[0];
    std::vector<uint8_t> payload(data.begin() + 1, data.end());

    switch (type) {
        case CLIENT_SETUP:
            return parse_client_setup(payload);
        case SERVER_SETUP:
            return parse_server_setup(payload);
        case SUBSCRIBE:
            return parse_subscribe(payload);
        default:
            return "Unsupported or unimplemented message type: 0x" + std::to_string(type);
    }
}

} // namespace moqt
