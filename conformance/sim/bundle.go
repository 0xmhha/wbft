package sim

import (
	"encoding/binary"
	"math/rand/v2"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// Template makes a scenario of the bundle for a seed. keys are test keys,
// at least Needs of them.
type Template struct {
	Name  string
	Needs int
	Make  func(seed int64, keys []Validator) Scenario
}

// Bundle returns the scenario bundle of the simulation tests: normal
// progress, a stopped round-0 proposer, two stopped consecutive proposers,
// a partition that heals, validators added and removed at epoch blocks, an
// import slower than the round timeout, restarts at random moments and in
// the middle of a height, a proposal that fails execution, a validator that
// signs two values in one view, a flood of invalid messages, a flood of
// validly signed messages, a peer that overflows its receive queue and a
// node whose clock is ahead.
// Every seed adds a crash and restart of one honest node at a random moment
// to the scenarios that do not stop nodes themselves.
func Bundle() []Template {
	return []Template{
		{"normal", 4, normal},
		{"proposer_stop", 4, proposerStop},
		{"two_proposers_stop", 7, twoProposersStop},
		{"partition_heal", 4, partitionHeal},
		{"epoch_change", 6, epochChange},
		{"slow_import", 4, slowImport},
		{"restarts", 4, restarts},
		{"bad_block", 4, badBlock},
		{"double_signer", 4, doubleSigner},
		{"invalid_flood", 4, invalidFlood},
		{"valid_flood", 4, validFlood},
		{"inbound_overflow", 4, inboundOverflow},
		{"clock_skew", 4, clockSkew},
	}
}

func seedRand(seed int64, salt uint64) *rand.Rand { return rand.New(rand.NewPCG(uint64(seed), salt)) }

func base(name string, seed int64, keys []Validator, n int, height uint64) Scenario {
	return Scenario{Name: name, Seed: seed, Validators: append([]Validator(nil), keys[:n]...), Until: Stop{Height: height, Duration: 3 * time.Minute}}
}

func ms(r *rand.Rand, lo, hi int) time.Duration {
	return time.Duration(lo+r.IntN(hi-lo+1)) * time.Millisecond
}

// mixRestart crashes one random non-adversary node at a random moment and
// restarts it a little later.
func mixRestart(sc *Scenario, r *rand.Rand, nodes int) {
	skip := map[types.Address]bool{}
	for _, a := range sc.Adversaries {
		skip[a.Node] = true
	}
	for tries := 0; tries < 10; tries++ {
		v := sc.Validators[r.IntN(nodes)]
		a := addrOf(v)
		if skip[a] {
			continue
		}
		at := ms(r, 500, 6000)
		sc.Schedule = append(sc.Schedule,
			NodeEvent{At: at, Node: a, Action: ActionCrash},
			NodeEvent{At: at + ms(r, 100, 3000), Node: a, Action: ActionRestart})
		return
	}
}

func addrOf(v Validator) types.Address {
	if v.address != (types.Address{}) {
		return v.address
	}
	x, err := NewValidator(v.ECDSA)
	if err != nil {
		return types.Address{}
	}
	return x.address
}

func normal(seed int64, keys []Validator) Scenario {
	sc := base("normal", seed, keys, 4, 8)
	mixRestart(&sc, seedRand(seed, 1), 4)
	return sc
}

// proposerStop stops one node (a round-0 proposer of some height) for a
// few seconds.
func proposerStop(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 2)
	sc := base("proposer_stop", seed, keys, 4, 8)
	a := addrOf(sc.Validators[r.IntN(4)])
	at := ms(r, 800, 3000)
	action := ActionStop
	if r.IntN(2) == 0 {
		action = ActionCrash
	}
	sc.Schedule = []NodeEvent{{At: at, Node: a, Action: action}, {At: at + ms(r, 2000, 8000), Node: a, Action: ActionRestart}}
	return sc
}

// twoProposersStop stops two nodes that follow each other in the set: two
// consecutive proposers.
func twoProposersStop(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 3)
	sc := base("two_proposers_stop", seed, keys, 7, 7)
	i := r.IntN(7)
	a, b := addrOf(sc.Validators[i]), addrOf(sc.Validators[(i+1)%7])
	at := ms(r, 800, 3000)
	back := at + ms(r, 3000, 9000)
	sc.Schedule = []NodeEvent{{At: at, Node: a, Action: ActionCrash}, {At: at, Node: b, Action: ActionCrash},
		{At: back, Node: a, Action: ActionRestart}, {At: back + ms(r, 0, 2000), Node: b, Action: ActionRestart}}
	return sc
}

// partitionHeal splits the validators into two halves without a quorum and
// joins them again.
func partitionHeal(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 4)
	sc := base("partition_heal", seed, keys, 4, 7)
	perm := r.Perm(4)
	var cut [][2]types.Address
	for _, x := range perm[:2] {
		for _, y := range perm[2:] {
			cut = append(cut, [2]types.Address{addrOf(sc.Validators[x]), addrOf(sc.Validators[y])})
		}
	}
	from := ms(r, 500, 3000)
	sc.Partitions = []Partition{{From: from, To: from + ms(r, 2000, 10000), Cut: cut}}
	mixRestart(&sc, r, 4)
	return sc
}

// epochChange adds validators at the first epoch block and removes one at
// the second.
func epochChange(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 5)
	sc := base("epoch_change", seed, keys, 6, 13)
	sc.Genesis = 4
	sc.Params.EpochLength = 4
	drop := r.IntN(4)
	var second []int
	for i := 0; i < 6; i++ {
		if i != drop {
			second = append(second, i)
		}
	}
	sc.Epochs = []EpochChange{{Block: 4, Candidates: []int{0, 1, 2, 3, 4, 5}}, {Block: 8, Candidates: second}}
	if r.IntN(2) == 0 {
		mixRestart(&sc, r, 6)
	}
	return sc
}

// slowImport makes one node import a decided block more slowly than the
// rest of its round timeout.
func slowImport(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 6)
	sc := base("slow_import", seed, keys, 4, 7)
	sc.App.SlowImport = []SlowImport{{Node: addrOf(sc.Validators[r.IntN(4)]), Height: uint64(2 + r.IntN(3)), Delay: ms(r, 2500, 5000)}}
	mixRestart(&sc, r, 4)
	return sc
}

// restarts crashes up to two nodes at random moments, one of them at a
// moment within a height (between a PRE-PREPARE and the decision).
func restarts(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 7)
	sc := base("restarts", seed, keys, 4, 8)
	for k := 0; k < 1+r.IntN(2); k++ {
		a := addrOf(sc.Validators[r.IntN(4)])
		// Heights start about every second; a moment 5..60 ms into a
		// second falls between the proposal and the decision.
		at := time.Duration(1+r.IntN(5))*time.Second + ms(r, 5, 60)
		action := ActionCrash
		if r.IntN(3) == 0 {
			action = ActionStop
		}
		sc.Schedule = append(sc.Schedule, NodeEvent{At: at, Node: a, Action: action},
			NodeEvent{At: at + ms(r, 50, 2500), Node: a, Action: ActionRestart})
	}
	return sc
}

// badBlock makes the blocks one node builds at some heights fail execution.
func badBlock(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 8)
	sc := base("bad_block", seed, keys, 4, 8)
	a := addrOf(sc.Validators[r.IntN(4)])
	for h := uint64(2); h <= 6; h++ {
		sc.App.BadProposals = append(sc.App.BadProposals, BadProposal{Height: h, Proposer: a})
	}
	mixRestart(&sc, r, 4)
	return sc
}

// clockSkew runs one node with its wall clock ahead: its proposals are
// from the future for the others, which defer them.
func clockSkew(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 13)
	sc := base("clock_skew", seed, keys, 4, 8)
	skewed := r.IntN(4)
	for i := 0; i < 4; i++ {
		spec := DefaultNode()
		if i == skewed {
			spec.ClockSkew = ms(r, 1100, 1900)
		}
		sc.Nodes = append(sc.Nodes, spec)
	}
	mixRestart(&sc, r, 4)
	return sc
}

// signVote signs a PREPARE or COMMIT for digest with the key and a seal
// over the header data of digest's proposal when known.
func signVote(secret []byte, code codec.Code, v types.View, digest types.Hash, sealData []byte) []byte {
	k, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		return nil
	}
	bk, err := bls.DeriveSecretKey(secret)
	if err != nil {
		return nil
	}
	m := &codec.Message{Code: code, View: v, Digest: digest, Seal: bk.Sign(sealData).Bytes()}
	p, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		return nil
	}
	if m.Signature, err = ecdsa.SignData(p, k); err != nil {
		return nil
	}
	b, err := codec.EncodeMessage(m)
	if err != nil {
		return nil
	}
	return b
}

// doubleSigner is a validator that sends its PREPAREs and COMMITs to half
// of its peers with another digest: two validly signed values in one view.
func doubleSigner(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 9)
	sc := base("double_signer", seed, keys, 4, 7)
	bad := addrOf(sc.Validators[r.IntN(4)])
	sc.Adversaries = []Adversary{{Node: bad, Rewrite: func(c *AdvContext, to types.Address, code uint64, payload []byte) []Wire {
		if code != uint64(codec.CodePrepare) && code != uint64(codec.CodeCommit) || to[19]%2 == 0 {
			return []Wire{{code, payload}}
		}
		m, err := codec.DecodeMessage(codec.Code(code), payload)
		if err != nil {
			return []Wire{{code, payload}}
		}
		other := keccak.Sum256(m.Digest[:], []byte("other"))
		return []Wire{{code, signVote(c.Secret, codec.Code(code), m.View, other, other[:])}}
	}}}
	mixRestart(&sc, r, 4)
	return sc
}

// invalidFlood sends a stream of messages with broken signatures to one
// node.
func invalidFlood(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 10)
	sc := base("invalid_flood", seed, keys, 4, 7)
	bad := addrOf(sc.Validators[r.IntN(4)])
	sc.Adversaries = []Adversary{{Node: bad, Every: 5 * time.Millisecond, From: 500 * time.Millisecond, Until: 8 * time.Second,
		Tick: func(c *AdvContext) {
			if len(c.Peers) == 0 {
				return
			}
			to := c.Peers[0]
			v := types.View{Sequence: c.View.Sequence, Round: c.View.Round}
			p := signVote(c.Secret, codec.CodePrepare, v, types.Hash{byte(c.Rand.IntN(256))}, []byte("x"))
			if len(p) > 10 {
				p[len(p)-5] ^= 0xff // break the signature
			}
			c.Send(to, uint64(codec.CodePrepare), p)
		}}}
	mixRestart(&sc, r, 4)
	return sc
}

// floodTick sends validly signed messages of the adversary for views in
// the receive window of the target.
func floodTick(perTick int) func(c *AdvContext) {
	return func(c *AdvContext) {
		if len(c.Peers) == 0 {
			return
		}
		to := c.Peers[0]
		for i := 0; i < perTick; i++ {
			v := types.View{Sequence: c.View.Sequence, Round: c.View.Round.AddUint64(uint64(c.Rand.IntN(5)))}
			code := codec.CodePrepare
			if c.Rand.IntN(2) == 0 {
				code = codec.CodeCommit
			}
			d := types.Hash{byte(c.Rand.IntN(256)), byte(c.Rand.IntN(256))}
			c.Send(to, uint64(code), signVote(c.Secret, code, v, d, d[:]))
		}
	}
}

// validFlood is a validator that floods one node with validly signed
// PREPAREs and COMMITs.
func validFlood(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 11)
	sc := base("valid_flood", seed, keys, 4, 7)
	bad := addrOf(sc.Validators[r.IntN(4)])
	sc.Adversaries = []Adversary{{Node: bad, Every: 5 * time.Millisecond, From: 300 * time.Millisecond, Until: 8 * time.Second, Tick: floodTick(4)}}
	mixRestart(&sc, r, 4)
	return sc
}

// inboundOverflow is a validator that sends more than the receive queue of
// one node holds.
func inboundOverflow(seed int64, keys []Validator) Scenario {
	r := seedRand(seed, 12)
	sc := base("inbound_overflow", seed, keys, 4, 7)
	bad := addrOf(sc.Validators[r.IntN(4)])
	target := addrOf(sc.Validators[(r.IntN(3)+1+indexOf(sc.Validators, bad))%4])
	// One delay on the flooding link: a burst arrives at one moment.
	sc.Links = []Link{{From: bad, To: target, Delay: []time.Duration{10 * time.Millisecond}}}
	sc.Adversaries = []Adversary{{Node: bad, Every: 50 * time.Millisecond, From: 300 * time.Millisecond, Until: 3 * time.Second,
		Tick: func(c *AdvContext) {
			for i := 0; i < 400; i++ {
				// An undecodable list, distinct for every message.
				p := []byte{0xc9, 0x88, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.BigEndian.PutUint64(p[2:], uint64(c.Now/time.Millisecond)<<16|uint64(i))
				c.Send(target, uint64(codec.CodeRoundChange), p)
			}
		}}}
	return sc
}

func indexOf(vs []Validator, a types.Address) int {
	for i, v := range vs {
		if addrOf(v) == a {
			return i
		}
	}
	return 0
}
