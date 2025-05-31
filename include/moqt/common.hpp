// Declaration of MoQT utility functions

#ifndef MOQT_COMMON_HPP
#define MOQT_COMMON_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace moqt {

// Reads a variable-length integer from the buffer starting at offset.
// Advances offset to the next unread position.
uint64_t read_varint(const std::vector<uint8_t>& data, size_t& offset);

// Reads a length-prefixed UTF-8 string (varint length + bytes) from buffer.
// Advances offset appropriately.
std::string read_lp_string(const std::vector<uint8_t>& data, size_t& offset);

} // namespace moqt

#endif // MOQT_COMMON_HPP
