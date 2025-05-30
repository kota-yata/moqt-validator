package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kota-yata/moqt-validator/internal/cli"
	"github.com/kota-yata/moqt-validator/pkg/moqt"
)

func main() {
	var (
		hexData  = flag.String("hex", "", "Validate hex-encoded message")
		filePath = flag.String("file", "", "Validate message from file")
		msgType  = flag.String("type", "control", "Message type (control, stream, datagram)")
		jsonOut  = flag.Bool("json", false, "Output as JSON")
	)

	flag.Parse()

	if *hexData == "" && *filePath == "" {
		fmt.Fprintln(os.Stderr, "Please provide either -hex or -file")
		flag.Usage()
		os.Exit(1)
	}

	var data []byte
	var err error

	if *hexData != "" {
		cleanHex := strings.Map(func(r rune) rune {
			if r != ' ' && r != '\t' && r != '\n' {
				return r
			}
			return -1
		}, *hexData)

		data, err = hex.DecodeString(cleanHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex: %v\n", err)
			os.Exit(1)
		}
	} else {
		data, err = os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	}

	validator := moqt.NewValidator()
	var result moqt.ValidationResult

	switch *msgType {
	case "control":
		result, err = validator.ValidateMessage(data, true)
	case "stream":
		result, err = validator.ValidateMessage(data, false)
	case "datagram":
		result, err = validator.ValidateDatagram(data)
	default:
		fmt.Fprintf(os.Stderr, "Invalid message type: %s\n", *msgType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Validation failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error producing JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Printf("\n=== MoQT %s Message Validation ===\n", strings.ToUpper(*msgType))
		cli.PrintValidationResult(result, 0)
		fmt.Println("\n✓ Validation successful")
	}
}
