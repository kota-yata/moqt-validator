// validator.hpp
// Declaration for top-level MoQT message validation

#ifndef MOQT_VALIDATOR_HPP
#define MOQT_VALIDATOR_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace moqt {

// Validates a full MoQT control message buffer
// Returns a diagnostic string or parse error
std::string validate_control_message(const std::vector<uint8_t>& data);

} // namespace moqt

#endif // MOQT_VALIDATOR_HPP
