// control_parser.hpp
// Declarations for MoQT control message parsing

#ifndef MOQT_CONTROL_PARSER_HPP
#define MOQT_CONTROL_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace moqt {

// Parses a SUBSCRIBE message and returns a descriptive string
std::string parse_subscribe(const std::vector<uint8_t>& payload);

// Parses a CLIENT_SETUP message and returns a descriptive string
std::string parse_client_setup(const std::vector<uint8_t>& payload);

// Parses a SERVER_SETUP message and returns a descriptive string
std::string parse_server_setup(const std::vector<uint8_t>& payload);

// Enum for known control message types
enum MoqtControlType : uint8_t {
    CLIENT_SETUP = 0x01,
    SERVER_SETUP = 0x02,
    SUBSCRIBE = 0x03,
    SUBSCRIBE_OK = 0x04,
    SUBSCRIBE_ERROR = 0x05
};

} // namespace moqt

#endif // MOQT_CONTROL_PARSER_HPP
