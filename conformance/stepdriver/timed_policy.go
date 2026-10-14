package stepdriver

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"
)

// MarshalJSON uses decimal strings so policy values remain exact in browsers.
func (p TimerPolicy) MarshalJSON() ([]byte, error) {
	out := map[string]string{}
	if p.RequestTimeoutSeconds != nil {
		out["request_timeout_seconds"] = strconv.FormatUint(*p.RequestTimeoutSeconds, 10)
	}
	if p.MaxRequestTimeoutSeconds != nil {
		out["max_request_timeout_seconds"] = strconv.FormatUint(*p.MaxRequestTimeoutSeconds, 10)
	}
	return json.Marshal(out)
}

// UnmarshalJSON refuses duplicate fields, numeric rounding and unsupported knobs.
func (p *TimerPolicy) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 {
		return ErrTimerPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrTimerPolicy
	}
	out := TimerPolicy{}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return ErrTimerPolicy
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return ErrTimerPolicy
		}
		seen[key] = true
		var value string
		if d.Decode(&value) != nil || value == "" || len(value) > 1 && value[0] == '0' {
			return ErrTimerPolicy
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return ErrTimerPolicy
			}
		}
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || n > uint64(math.MaxInt64/int64(time.Second)) {
			return ErrTimerPolicy
		}
		switch key {
		case "request_timeout_seconds":
			if n == 0 {
				return ErrTimerPolicy
			}
			out.RequestTimeoutSeconds = &n
		case "max_request_timeout_seconds":
			out.MaxRequestTimeoutSeconds = &n
		default:
			return ErrTimerPolicy
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) == 0 {
		return ErrTimerPolicy
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrTimerPolicy
	}
	*p = out
	return nil
}
