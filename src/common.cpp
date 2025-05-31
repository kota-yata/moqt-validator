// common.cpp
// Utility functions for MoQT parsing: varint and length-prefixed strings

#include <moqt/common.hpp>
#include <stdexcept>
#include <string>
#include <vector>

uint64_t moqt::read_varint(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset >= data.size()) throw std::out_of_range("Unexpected end of buffer");
    uint8_t first = data[offset];
    if ((first & 0x80) == 0) return data[offset++];
    if ((first & 0xC0) == 0x80) {
        if (offset + 1 >= data.size()) throw std::out_of_range("Incomplete varint");
        uint64_t val = ((first & 0x3F) << 8) | data[offset + 1];
        offset += 2;
        return val;
    }
    throw std::runtime_error("Unsupported varint format");
}

std::string moqt::read_lp_string(const std::vector<uint8_t>& data, size_t& offset) {
    uint64_t len = read_varint(data, offset);
    if (offset + len > data.size()) throw std::out_of_range("String length exceeds buffer");
    std::string result(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return result;
}
