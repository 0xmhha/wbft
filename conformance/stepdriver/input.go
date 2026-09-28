package stepdriver

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ErrInput reports a case input that does not follow the steps format.
var ErrInput = errors.New("stepdriver: malformed case input")

// hexb is a byte string of the vector format: "0x" and lowercase hex digits.
type hexb []byte

func (h *hexb) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	if !strings.HasPrefix(s, "0x") {
		return fmt.Errorf("%w: byte string %q without 0x", ErrInput, s)
	}
	v, err := hex.DecodeString(s[2:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	*h = v
	return nil
}

// dec is a non-negative integer of the vector format: a decimal string.
type dec struct{ big.Int }

func (d *dec) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	if _, ok := d.SetString(s, 10); !ok || d.Sign() < 0 || s == "" || (len(s) > 1 && s[0] == '0') {
		return fmt.Errorf("%w: integer %q", ErrInput, s)
	}
	return nil
}

func (d *dec) uint64() (uint64, error) {
	if !d.IsUint64() {
		return 0, fmt.Errorf("%w: integer %s out of range", ErrInput, d.String())
	}
	return d.Uint64(), nil
}

// caseInput is input.yaml of a steps case of the runners state_machine and
// network (A-11 section 3.1).
type caseInput struct {
	Initial initialInput `json:"initial"`
	Steps   []stepInput  `json:"steps"`
}

type initialInput struct {
	Validators []struct {
		Address      hexb `json:"address"`
		BLSPublicKey hexb `json:"bls_public_key"`
	} `json:"validators"`
	ProposerPolicy dec  `json:"proposer_policy"`
	NodeKey        hexb `json:"node_key"`
	Head           hexb `json:"head"`
	App            struct {
		InvalidProposals []hexb `json:"invalid_proposals"`
		FutureProposals  []hexb `json:"future_proposals"`
		BadBlocks        []hexb `json:"bad_blocks"`
		Finalize         string `json:"finalize"`
	} `json:"app"`
	// Network runner only.
	Engine        *string `json:"engine"`
	Synchronising *bool   `json:"synchronising"`
	Peers         []hexb  `json:"peers"`
}

type stepInput struct {
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Code    *dec   `json:"code"`
	Payload hexb   `json:"payload"`
	Block   hexb   `json:"block"`
	Timer   *dec   `json:"timer"`
	Round   *dec   `json:"round"`
	Notify  *bool  `json:"notify"`
	Peer    hexb   `json:"peer"`
}

// parseInput decodes a case input, rejecting unknown fields so that a change
// of the format is noticed.
func parseInput(input json.RawMessage) (*caseInput, error) {
	var in caseInput
	d := json.NewDecoder(strings.NewReader(string(input)))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInput, err)
	}
	return &in, nil
}
