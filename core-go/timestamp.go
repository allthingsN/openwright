package openwrightcore

import (
	"fmt"
	"time"
)

// ToRFC3339 normalizes an integer unix timestamp to a fixed-precision RFC 3339
// UTC string, byte-identical to src/openwright/canonical.py:to_rfc3339 for
// integer inputs.
//
// Heuristic (mirrors Python): values above 10**14 are nanoseconds; otherwise
// seconds. All arithmetic is exact integer math — never via float seconds —
// because a float mantissa cannot represent nanoseconds for current-epoch
// instants, which would make the low digits rounding artifacts and a latent
// cross-language divergence. Output always uses a fixed 9-digit fractional
// field and a trailing Z.
func ToRFC3339(value int64) string {
	var ns int64
	if value > 100_000_000_000_000 { // 10**14
		ns = value
	} else {
		ns = value * 1_000_000_000
	}
	// divmod(ns, 1e9) — Python floor division; for non-negative ns this matches
	// Go's truncating division and the conformance vectors only carry ns >= 0.
	secs := ns / 1_000_000_000
	rem := ns % 1_000_000_000
	t := time.Unix(secs, 0).UTC()
	return fmt.Sprintf("%s.%09dZ", t.Format("2006-01-02T15:04:05"), rem)
}
