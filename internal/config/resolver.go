// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package config

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// InitResolver checks if useStdin is true. If so, it reads the API key securely from stdin
// and injects it into the in-memory environment, shielding it from /proc snooping.
func InitResolver(useStdin bool) error {
	if useStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read API key from stdin: %w", err)
		}
		key := strings.TrimSpace(string(data))
		if key != "" {
			return os.Setenv("NETSHIELD_API_KEY", key)
		}
	}
	return nil
}
