MoQT Validator

moqt-validator/
├── cmd/
│   └── moqt-validator/
│       └── main.go              # CLI entry point
├── pkg/
│   └── moqt/
│       ├── constants.go         # All protocol constants
│       ├── types.go            # Core types and structures
│       ├── errors.go           # Error definitions
│       ├── varint.go           # VarInt encoding/decoding
│       ├── validator.go        # Main validator struct and methods
│       ├── control.go          # Control message validation
│       ├── data.go             # Data stream validation
│       ├── datagram.go         # Datagram validation
│       ├── parameters.go       # Parameter parsing
│       ├── auth.go             # Authorization token handling
│       ├── extensions.go       # Extension header validation
│       └── helpers.go          # Utility functions
├── internal/
│   └── cli/
│       └── output.go           # CLI output formatting
├── test/
│   ├── testdata/               # Test message samples
│   ├── validator_test.go       # Main validator tests
│   ├── control_test.go         # Control message tests
│   ├── data_test.go           # Data stream tests
│   └── datagram_test.go       # Datagram tests
├── go.mod
├── go.sum
├── README.md
└── Makefile
