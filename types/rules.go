package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	"github.com/0xmhha/wbft/crypto/keccak"
)

// RuleName identifies a chain-level rule, independent of the node profile.
type RuleName string

// RejectNumberJump is the header number rule of the chain configuration.
const RejectNumberJump RuleName = "rejectNumberJump"

// MinimalSealerBitmap requires aggregate bitmaps without trailing zero bytes.
const MinimalSealerBitmap RuleName = "minimalSealerBitmap"

// StableCandidateSort orders equal-score candidates by their input position.
const StableCandidateSort RuleName = "stableCandidateSort"

// FirstProposerDiligenceCap uses the prior set for the first proposer bound.
const FirstProposerDiligenceCap RuleName = "firstProposerDiligenceCap"

// Rules reports whether name is enabled at the full height at.
// Missing or null activation heights are disabled.
func (c *Config) Rules(name RuleName, at Height) bool {
	h, ok := c.rules[name]
	return ok && at.Cmp(h) >= 0
}

// RuleActivation returns the configured full activation height, if enabled.
func (c *Config) RuleActivation(name RuleName) (Height, bool) {
	h, ok := c.rules[name]
	return h, ok
}

// RuleActivations returns a copy of the configured activation heights.
func (c *Config) RuleActivations() map[RuleName]string {
	out := make(map[RuleName]string, len(c.rules))
	for name, h := range c.rules { //wbft:unordered output map, not an evaluation order
		out[name] = h.String()
	}
	return out
}

// RulesDigest covers anzeon.wbft, transitions and every wbftRules group.
// Configurations constructed without JSON have the zero digest.
func (c *Config) RulesDigest() Hash { return c.rulesDigest }

func parseConsensusRules(raw []byte) (map[RuleName]Height, error) {
	var cc struct {
		Rules map[string]json.RawMessage `json:"wbftRules"`
	}
	if err := json.Unmarshal(raw, &cc); err != nil {
		return nil, &ErrConfig{Field: "wbftRules", Reason: err.Error()}
	}
	out := make(map[RuleName]Height)
	for _, group := range ConsensusRulesGroups {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(cc.Rules[group], &keys); err != nil {
			if len(cc.Rules[group]) == 0 {
				continue
			}
			return nil, &ErrConfig{Field: "wbftRules." + group, Reason: err.Error()}
		}
		names := make([]string, 0, len(keys))
		for name := range keys { //wbft:unordered sorted below
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			field := "wbftRules." + group + "." + name
			if group != "consensusRules" || RuleName(name) != RejectNumberJump && RuleName(name) != MinimalSealerBitmap && RuleName(name) != StableCandidateSort && RuleName(name) != FirstProposerDiligenceCap {
				return nil, &ErrConfig{Field: field, Reason: "unknown rule"}
			}
			value := strings.TrimSpace(string(keys[name]))
			if value == "null" {
				continue
			}
			// An activation is a non-negative JSON integer, never a float or string.
			if len(value) == 0 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, &ErrConfig{Field: field, Reason: "activation must be a non-negative integer or null"}
			}
			n, ok := new(big.Int).SetString(value, 10)
			if !ok {
				return nil, &ErrConfig{Field: field, Reason: "invalid activation"}
			}
			out[RuleName(name)] = MustHeightFromBig(n)
		}
	}
	return out, nil
}

func chainRulesDigest(raw []byte) (Hash, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var cc map[string]any
	if err := d.Decode(&cc); err != nil {
		return Hash{}, err
	}
	var wbft any
	if anzeon, ok := cc["anzeon"].(map[string]any); ok {
		wbft = anzeon["wbft"]
	}
	selected := map[string]any{"anzeon": map[string]any{"wbft": wbft}, "transitions": cc["transitions"], "wbftRules": cc["wbftRules"]}
	canonicalNumbers(selected)
	// encoding/json sorts object keys and keeps array order. UseNumber and
	// canonicalNumber preserve every digit without a floating-point conversion.
	b, err := json.Marshal(selected)
	if err != nil {
		return Hash{}, err
	}
	return keccak.Sum256(b), nil
}

func canonicalNumbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x { //wbft:unordered independent normalization of each key
			x[k] = canonicalNumbers(value)
		}
	case []any:
		for i, value := range x {
			x[i] = canonicalNumbers(value)
		}
	case json.Number:
		return canonicalNumber(x)
	}
	return v
}

// canonicalNumber writes a decimal coefficient without trailing zeroes and
// a base-ten exponent; zero is "0" and a zero exponent is omitted.
func canonicalNumber(n json.Number) json.Number {
	s := string(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	exponent := new(big.Int)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent.SetString(s[i+1:], 10)
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(s)-i-1)))
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	trimmed := strings.TrimRight(s, "0")
	exponent.Add(exponent, big.NewInt(int64(len(s)-len(trimmed))))
	if exponent.Sign() == 0 {
		return json.Number(sign + trimmed)
	}
	return json.Number(sign + trimmed + "e" + exponent.String())
}
