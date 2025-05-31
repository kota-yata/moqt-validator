// control_parser.cpp
// Handles parsing of MoQT control messages

#include <moqt/control_parser.hpp>
#include <moqt/common.hpp> 
#include <sstream>
#include <stdexcept>

namespace moqt {

std::string parse_subscribe(const std::vector<uint8_t>& payload) {
    size_t offset = 0;
    std::ostringstream report;
    try {
        uint64_t request_id = read_varint(payload, offset);
        uint64_t track_alias = read_varint(payload, offset);
        report << "SUBSCRIBE: request_id=" << request_id << ", track_alias=" << track_alias;
    } catch (const std::exception& e) {
        return std::string("SUBSCRIBE parse error: ") + e.what();
    }
    return report.str();
}

std::string parse_client_setup(const std::vector<uint8_t>& payload) {
    size_t offset = 0;
    std::ostringstream report;
    try {
        uint64_t version_count = read_varint(payload, offset);
        report << "CLIENT_SETUP: versions=" << version_count;
        for (uint64_t i = 0; i < version_count; ++i) {
            uint64_t version = read_varint(payload, offset);
            report << " v" << version;
        }
        report << "; Params=";
        while (offset < payload.size()) {
            uint64_t param_type = read_varint(payload, offset);
            std::string param_value = read_lp_string(payload, offset);
            report << " [" << param_type << ":" << param_value << "]";
        }
    } catch (const std::exception& e) {
        return std::string("CLIENT_SETUP parse error: ") + e.what();
    }
    return report.str();
}

std::string parse_server_setup(const std::vector<uint8_t>& payload) {
    size_t offset = 0;
    std::ostringstream report;
    try {
        uint64_t version = read_varint(payload, offset);
        report << "SERVER_SETUP: version=" << version << "; Params=";
        while (offset < payload.size()) {
            uint64_t param_type = read_varint(payload, offset);
            std::string param_value = read_lp_string(payload, offset);
            report << " [" << param_type << ":" << param_value << "]";
        }
    } catch (const std::exception& e) {
        return std::string("SERVER_SETUP parse error: ") + e.what();
    }
    return report.str();
}

} // namespace moqt
