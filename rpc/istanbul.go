package rpc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// The compatible istanbul namespace (spec B-09 §8, observe.md 6): the eight
// methods of the reference, with its input reading, results and error
// texts, so that tools written for go-stablenet read a wbft node alike.

// Block number tags (B-09 §1).
const (
	SafeBlockNumber      BlockNumber = -4
	FinalizedBlockNumber BlockNumber = -3
	LatestBlockNumber    BlockNumber = -2
	PendingBlockNumber   BlockNumber = -1
	EarliestBlockNumber  BlockNumber = 0
)

// BlockNumber is a block number argument: a QUANTITY or one of the tags
// earliest, latest, pending, finalized and safe, read as go-ethereum's
// rpc.BlockNumber reads it.
type BlockNumber int64

// UnmarshalJSON implements json.Unmarshaler.
func (bn *BlockNumber) UnmarshalJSON(data []byte) error {
	input := strings.TrimSpace(string(data))
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}
	switch input {
	case "earliest":
		*bn = EarliestBlockNumber
		return nil
	case "latest":
		*bn = LatestBlockNumber
		return nil
	case "pending":
		*bn = PendingBlockNumber
		return nil
	case "finalized":
		*bn = FinalizedBlockNumber
		return nil
	case "safe":
		*bn = SafeBlockNumber
		return nil
	}
	n, err := decodeUint64(input)
	if err != nil {
		return err
	}
	if n > math.MaxInt64 {
		return errors.New("block number larger than int64")
	}
	*bn = BlockNumber(n)
	return nil
}

// decodeUint64 reads a QUANTITY as go-ethereum's hexutil.DecodeUint64
// does, with its error texts (wbft does not import that package).
func decodeUint64(input string) (uint64, error) {
	if len(input) == 0 {
		return 0, errors.New("empty hex string")
	}
	if len(input) < 2 || input[0] != '0' || (input[1] != 'x' && input[1] != 'X') {
		return 0, errors.New("hex string without 0x prefix")
	}
	raw := input[2:]
	if len(raw) == 0 {
		return 0, errors.New(`hex string "0x"`)
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, errors.New("hex number with leading zero digits")
	}
	n, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, errors.New("hex number > 64 bits")
		}
		return 0, errors.New("invalid hex string")
	}
	return n, nil
}

// The error texts of the reference.
var (
	errUnknownBlock = errors.New("unknown block")
	errEmptySeals   = errors.New("zero seals")
	errUnknownAnc   = errors.New("unknown ancestor")
)

// maxStatusBlockRange is MAX_STATUS_BLOCK_RANGE (B-09 §8.5).
const maxStatusBlockRange = 1024

// IstanbulService is the istanbul namespace. It exports exactly the eight
// methods of the reference (SNET-RPC-041).
type IstanbulService struct{ b Backend }

// BlockSigners is the result of istanbul_getCommitSignersFromBlock(ByHash);
// like the reference it has no JSON tags.
type BlockSigners struct {
	Number     uint64
	Hash       types.Hash
	Author     types.Address
	Committers []types.Address
}

// SealerActivity, BlockRange, RoundStats and Status are the result of
// istanbul_status.
type SealerActivity struct {
	Total         map[types.Address]int `json:"total"`
	Prepared      map[types.Address]int `json:"prepared"`
	Committed     map[types.Address]int `json:"committed"`
	PrevPrepared  map[types.Address]int `json:"prevPrepared"`
	PrevCommitted map[types.Address]int `json:"prevCommitted"`
}

// BlockRange is the block range of istanbul_status.
type BlockRange struct {
	StartBlock  uint64 `json:"startBlock"`
	EndBlock    uint64 `json:"endBlock"`
	TotalBlocks uint64 `json:"totalBlocks"`
}

// RoundStats is the round distribution of istanbul_status.
type RoundStats struct {
	RoundDistribution map[uint64]uint64 `json:"roundDistribution"`
}

// Status is istanbul_status.
type Status struct {
	SealerActivity SealerActivity        `json:"sealerActivity"`
	AuthorCounts   map[types.Address]int `json:"author"`
	BlockRange     BlockRange            `json:"blockRange"`
	RoundStats     RoundStats            `json:"roundStats"`
}

func (s *IstanbulService) head() *types.Header { return s.b.Chain().Head() }

// header reads the header of a number argument; nil and latest are the head
// and the other negative tags fall through as uint64, as in the reference.
func (s *IstanbulService) header(number *BlockNumber) *types.Header {
	if number == nil || *number == LatestBlockNumber {
		return s.head()
	}
	return s.b.Chain().HeaderByNumber(uint64(*number))
}

// validators is validators_at of a header: its address list.
func (s *IstanbulService) validators(h *types.Header) ([]types.Address, error) {
	cfg := s.b.ChainConfig()
	if cfg == nil {
		return nil, ErrNoConfig
	}
	vs, err := validator.ValidatorsAt(s.b.Chain(), cfg, h.Number, h.ParentHash, nil)
	if err != nil {
		return nil, err
	}
	return vs.Addresses(), nil
}

// forVerifying is the reference's GetValidatorsForVerifying: the set of h
// and the set of its parent (the same set for heights 0 and 1).
func (s *IstanbulService) forVerifying(h *types.Header) (cur, prev []types.Address, err error) {
	if cur, err = s.validators(h); err != nil {
		return nil, nil, errUnknownAnc
	}
	n := h.Number.RefLow64() //wbft:low64 HH-20
	if n < 2 {
		return cur, cur, nil
	}
	parent := s.b.Chain().Header(h.ParentHash, n-1)
	if parent == nil {
		return nil, nil, errUnknownAnc
	}
	if prev, err = s.validators(parent); err != nil {
		return nil, nil, err
	}
	return cur, prev, nil
}

// NodeAddress is istanbul_nodeAddress: the address the node signs with.
func (s *IstanbulService) NodeAddress() types.Address { return s.b.NodeInfo().Address }

// GetCommitSignersFromBlock is istanbul_getCommitSignersFromBlock.
func (s *IstanbulService) GetCommitSignersFromBlock(number *BlockNumber) (*BlockSigners, error) {
	h := s.header(number)
	if h == nil {
		return nil, errUnknownBlock
	}
	return s.commitSigners(h)
}

// GetCommitSignersFromBlockByHash is istanbul_getCommitSignersFromBlockByHash.
func (s *IstanbulService) GetCommitSignersFromBlockByHash(hash types.Hash) (*BlockSigners, error) {
	h := s.b.Chain().HeaderByHash(hash)
	if h == nil {
		return nil, errUnknownBlock
	}
	return s.commitSigners(h)
}

// commitSigners is the author (the coinbase, SNET-RPC-012) and the committed
// sealers in the EpochInfo that governs h (SNET-RPC-011).
func (s *IstanbulService) commitSigners(h *types.Header) (*BlockSigners, error) {
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	cfg := s.b.ChainConfig()
	if cfg == nil {
		return nil, ErrNoConfig
	}
	_, ei, err := validator.GoverningEpochInfo(s.b.Chain(), cfg, h, nil)
	if err != nil {
		return nil, err
	}
	if x.CommittedSeal == nil {
		return nil, errEmptySeals
	}
	idx := x.CommittedSeal.Sealers.Sealers()
	signers := make([]types.Address, len(idx))
	for i, k := range idx {
		if int(k) >= len(ei.Validators) { // the reference panics here
			return nil, fmt.Errorf("sealer index %d out of %d validators", k, len(ei.Validators))
		}
		v := ei.Candidate(ei.Validators[k])
		if v == (types.Address{}) {
			return nil, errors.New("validator address is zero")
		}
		signers[i] = v
	}
	return &BlockSigners{Number: h.Number.RefLow64(), Hash: codec.BlockHash(h), Author: h.Coinbase, Committers: signers}, nil //wbft:low64 HH-20
}

// GetValidators is istanbul_getValidators: validators_at(number) (SNET-RPC-013).
func (s *IstanbulService) GetValidators(number *BlockNumber) ([]types.Address, error) {
	h := s.header(number)
	if h == nil {
		return nil, errUnknownBlock
	}
	return s.validators(h)
}

// GetValidatorsAtHash is istanbul_getValidatorsAtHash.
func (s *IstanbulService) GetValidatorsAtHash(hash types.Hash) ([]types.Address, error) {
	h := s.b.Chain().HeaderByHash(hash)
	if h == nil {
		return nil, errUnknownBlock
	}
	return s.validators(h)
}

// IsValidator is istanbul_isValidator; a set that cannot be derived is false
// (SNET-RPC-014).
func (s *IstanbulService) IsValidator(number *BlockNumber) (bool, error) {
	var n BlockNumber
	if number != nil {
		n = *number
	} else {
		n = BlockNumber(s.head().Number.RefLow64()) //wbft:low64 HH-20
	}
	vals, _ := s.GetValidators(&n)
	self := s.NodeAddress()
	for _, v := range vals {
		if v == self {
			return true, nil
		}
	}
	return false, nil
}

// Status is istanbul_status (SNET-RPC-015 to -018).
func (s *IstanbulService) Status(start, end *BlockNumber) (*Status, error) {
	from, to, count, err := s.statusRange(start, end)
	if err != nil {
		return nil, err
	}
	act := SealerActivity{Total: map[types.Address]int{}, Prepared: map[types.Address]int{}, Committed: map[types.Address]int{},
		PrevPrepared: map[types.Address]int{}, PrevCommitted: map[types.Address]int{}}
	authors := map[types.Address]int{}
	rounds := map[uint64]uint64{}
	var cur, prev []types.Address
	for n := from; n <= to; n++ {
		r, err := s.analyzeBlock(n, &act, authors, &cur, &prev)
		if err != nil {
			return nil, err
		}
		rounds[r]++
	}
	return &Status{SealerActivity: act, AuthorCounts: authors, BlockRange: BlockRange{StartBlock: from, EndBlock: to, TotalBlocks: count},
		RoundStats: RoundStats{RoundDistribution: rounds}}, nil
}

func (s *IstanbulService) statusRange(start, end *BlockNumber) (uint64, uint64, uint64, error) {
	if start != nil && end == nil {
		return 0, 0, 0, errors.New("pass the end block number")
	}
	if start == nil && end != nil {
		return 0, 0, 0, errors.New("pass the start block number")
	}
	head := s.head().Number.RefLow64() //wbft:low64 HH-20
	var from, to uint64
	if start == nil {
		to = head
		if to >= 63 {
			from = to - 63
		}
	} else {
		resolve := func(n BlockNumber) (uint64, error) {
			if n >= 0 {
				return uint64(n), nil
			}
			if n == LatestBlockNumber {
				return head, nil
			}
			return 0, fmt.Errorf("unsupported block number: %d", n)
		}
		var err error
		if to, err = resolve(*end); err != nil {
			return 0, 0, 0, err
		}
		if from, err = resolve(*start); err != nil {
			return 0, 0, 0, err
		}
		if from > to {
			return 0, 0, 0, errors.New("start block number should be less than end block number")
		}
		if to > head {
			return 0, 0, 0, errors.New("end block number should be less than or equal to current block height")
		}
	}
	count := to - from + 1
	if count > maxStatusBlockRange {
		return 0, 0, 0, fmt.Errorf("requested range too large: %d blocks (max %d)", count, maxStatusBlockRange)
	}
	return from, to, count, nil
}

// analyzeBlock counts the seals and the author of block n; the sets are
// taken on the first block and after a block with an EpochInfo.
func (s *IstanbulService) analyzeBlock(n uint64, act *SealerActivity, authors map[types.Address]int, cur, prev *[]types.Address) (uint64, error) {
	h := s.b.Chain().HeaderByNumber(n)
	if h == nil {
		return 0, fmt.Errorf("block %d not found", n)
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return 0, fmt.Errorf("block %d: failed to extract WBFT extra: %w", n, err)
	}
	if *cur == nil {
		c, p, err := s.forVerifying(h)
		if err != nil {
			return 0, fmt.Errorf("block %d: failed to get validators: %w", n, err)
		}
		*cur, *prev = c, p
		zero := func(a types.Address, ms ...map[types.Address]int) {
			for _, m := range ms {
				if _, ok := m[a]; !ok {
					m[a] = 0
				}
			}
		}
		for _, a := range c {
			zero(a, act.Prepared, act.Committed, act.Total, authors, act.PrevPrepared, act.PrevCommitted)
		}
		for _, a := range p {
			zero(a, act.PrevPrepared, act.PrevCommitted, act.Total, authors)
		}
	}
	authors[h.Coinbase]++
	add := func(seal *types.AggregatedSeal, vals []types.Address, m map[types.Address]int) {
		if seal == nil {
			return
		}
		for _, i := range seal.Sealers.Sealers() {
			if int(i) < len(vals) {
				m[vals[i]]++
				act.Total[vals[i]]++
			}
		}
	}
	add(x.PreparedSeal, *cur, act.Prepared)
	add(x.CommittedSeal, *cur, act.Committed)
	add(x.PrevPreparedSeal, *prev, act.PrevPrepared)
	add(x.PrevCommittedSeal, *prev, act.PrevCommitted)
	if x.EpochInfo != nil {
		*cur = nil
	} else {
		*prev = *cur
	}
	return uint64(x.Round), nil
}

// GetWbftExtraInfo is istanbul_getWbftExtraInfo (SNET-RPC-019). number is
// required and not a pointer, so latest reads as -2 and is not found.
func (s *IstanbulService) GetWbftExtraInfo(number BlockNumber) (map[string]any, error) {
	h := s.b.Chain().HeaderByNumber(uint64(number))
	if h == nil {
		return nil, fmt.Errorf("block %d not found", big.NewInt(int64(number)))
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	cur, prev, err := s.forVerifying(h)
	if err != nil {
		return nil, err
	}
	gasTip := "<nil>"
	if x.GasTip != nil {
		gasTip = x.GasTip.String()
	}
	return map[string]any{
		"vanityData":        "0x" + hex.EncodeToString(x.VanityData),
		"randaoReveal":      "0x" + hex.EncodeToString(x.RandaoReveal),
		"prevRound":         fmt.Sprintf("0x%x", x.PrevRound),
		"prevPreparedSeal":  sealJSON(x.PrevPreparedSeal, prev),
		"prevCommittedSeal": sealJSON(x.PrevCommittedSeal, prev),
		"round":             fmt.Sprintf("0x%x", x.Round),
		"preparedSeal":      sealJSON(x.PreparedSeal, cur),
		"committedSeal":     sealJSON(x.CommittedSeal, cur),
		"gasTip":            gasTip,
		"epochInfo":         epochJSON(x.EpochInfo),
	}, nil
}

// sealJSON is a seal of istanbul_getWbftExtraInfo: the checksummed
// addresses of its sealers in vals and the signature; nil for no seal.
func sealJSON(seal *types.AggregatedSeal, vals []types.Address) map[string]any {
	if seal == nil {
		return nil
	}
	idx := seal.Sealers.Sealers()
	sealers := make([]string, 0, len(idx))
	for _, i := range idx {
		if int(i) < len(vals) {
			sealers = append(sealers, vals[i].Hex())
		}
	}
	return map[string]any{"sealers": sealers, "signature": "0x" + hex.EncodeToString(seal.Signature)}
}

// epochJSON is the EpochInfo of istanbul_getWbftExtraInfo; nil for none.
func epochJSON(ei *types.EpochInfo) map[string]any {
	if ei == nil {
		return nil
	}
	cands := make([]map[string]any, 0, len(ei.Candidates))
	for _, c := range ei.Candidates {
		cands = append(cands, map[string]any{"addr": c.Addr.Hex(), "diligence": fmt.Sprintf("0x%x", c.Diligence)})
	}
	vals := make([]map[string]any, 0, len(ei.Validators))
	for i, k := range ei.Validators {
		vals = append(vals, map[string]any{"index": fmt.Sprintf("0x%x", k), "addr": ei.Candidate(k).Hex(),
			"bls": "0x" + hex.EncodeToString(ei.BLSPublicKeys[i])})
	}
	return map[string]any{"candidates": cands, "validators": vals}
}
