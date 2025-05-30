package cli

import (
	"fmt"
	"strings"
)

// PrintValidationResult recursively prints a nested map with indentation.
// It handles slices, maps, and primitive values for pretty CLI display.
func PrintValidationResult(result map[string]interface{}, indent int) {
	prefix := strings.Repeat("  ", indent)

	for key, value := range result {
		switch v := value.(type) {
		case []interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					PrintValidationResult(m, indent+1)
				} else {
					fmt.Printf("%s  - %v\n", prefix, item)
				}
			}
		case []map[string]interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				PrintValidationResult(item, indent+1)
			}
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			PrintValidationResult(v, indent+1)
		case []string:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				fmt.Printf("%s  - %s\n", prefix, item)
			}
		default:
			fmt.Printf("%s%s: %v\n", prefix, key, value)
		}
	}
}
