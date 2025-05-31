MoQT Validator

moqt-validator/
├── CMakeLists.txt              # CMake build configuration
├── include/
│   └── moqt/
│       ├── common.hpp          # Common utilities: varint, error types, etc.
│       ├── control_parser.hpp  # Interfaces and structures for control parsing
│       ├── message_types.hpp   # Constants/enums for message types
│       └── validator.hpp       # API entry points for validation
├── src/
│   ├── common.cpp              # Implements varint reader, helpers
│   ├── control_parser.cpp      # Implementations for control messages
│   ├── validator.cpp           # validate_control_message logic
│   └── main.cpp                # CLI/test driver
├── test/
│   ├── test_utils.cpp          # Test harness
│   ├── control_tests.cpp       # Unit tests for control parsing
│   └── data_tests.cpp          # Future: data stream parsing tests
├── data/
│   └── samples/                # Binary test vectors
├── scripts/
│   └── gen_test_vectors.py     # Optional: scripts to generate encoded inputs
└── README.md

