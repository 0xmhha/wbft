package stepdriver

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestTimedActionsSeparateTimerPolicyFromSignedNetworkBytes(t *testing.T) {
	self, other := types.Address{1}, types.Address{2}
	validators, err := validator.NewSet([]types.Address{self, other}, [][]byte{{1}, {2}}, types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	height := types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 90))
	round, err := types.RoundFromBig(new(big.Int).Lsh(big.NewInt(1), 80))
	if err != nil {
		t.Fatal(err)
	}
	message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: height, Round: round}, Digest: types.Hash{3}}
	broadcast := consensus.Broadcast{Msg: message, Validators: validators, SealData: []byte{4}}
	arm := consensus.ArmTimer{Kind: consensus.RoundTimer, View: message.View, Duration: time.Second}
	source := TimedSource{Writer: "synthetic", Engine: 9007199254740993, Step: 9007199254740994, Ordinal: 9007199254740995}
	inputSource := source
	inputSource.Step++
	inputSource.Ordinal++
	signed := *message
	signed.Signature = []byte{5}
	signed.Seal = []byte{6}
	payload, err := codec.EncodeMessage(&signed)
	if err != nil {
		t.Fatal(err)
	}
	proof := timedSigningEvidence{Output: broadcast, Input: consensus.Message{Code: message.Code, Payload: payload}, Source: inputSource}
	first, err := timedActions([]consensus.Output{arm, broadcast}, self)
	if err != nil {
		t.Fatal(err)
	}
	arm.Duration = 2 * time.Second
	second, err := timedActions([]consensus.Output{arm, broadcast}, self)
	if err != nil {
		t.Fatal(err)
	}
	first[1].signed(proof, timedOutputKey{Source: source, Output: 1})
	second[1].signed(proof, timedOutputKey{Source: source, Output: 1})
	if first[0].SHA256 == second[0].SHA256 || first[1].SHA256 != second[1].SHA256 || first[1].PayloadSHA256 != second[1].PayloadSHA256 {
		t.Fatal("timer change treated as a network-byte change")
	}
	if first[1].SigningInput == nil || first[1].SigningInput.Step != inputSource.Step || first[1].SigningOutput.Source != source || first[1].SigningOutput.Output != "2" {
		t.Fatal("producer output and signing input conflated", first[1])
	}
	if first[1].RecipientEvidence != "validator_set" || len(first[1].EligibleRecipients) != 1 || first[1].EligibleRecipients[0] != strings.ToLower(other.Hex()) {
		t.Fatal("self treated as a network recipient")
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"engine_run":"9007199254740993"`) || strings.Contains(string(raw), message.Digest.Hex()) || strings.Contains(string(raw), `"payload":`) {
		t.Fatal("rounded or raw message metadata", string(raw))
	}
	if *first[1].Height != height.String() || *first[1].Round != round.String() {
		t.Fatal("full view lost")
	}
}
func TestTimedActionsPreserveOutputOrderAndApplicationViews(t *testing.T) {
	block := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(7)}}
	outputs := []consensus.Output{consensus.RequestBuild{Height: types.HeightFromUint64(8), Round: types.RoundFromUint64(3)}, consensus.Commit{Block: block, Round: types.RoundFromUint64(2)}, consensus.Schedule{In: consensus.Stop{}}, consensus.CancelTimers{Kinds: []consensus.TimerKind{consensus.RoundTimer}}, consensus.Outcome{}, consensus.Event{Record: event.Record{Kind: event.StateChange}}}
	actions, err := timedActions(outputs, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	for i, action := range actions {
		raw, err := inputlog.EncodeOutputs([]consensus.Output{outputs[i]})
		if err != nil || action.SHA256 != actionHash(raw) {
			t.Fatal("not bound to full encoded output", i, err)
		}
	}
	if actions[0].Kind != "request_build" || *actions[0].Height != "8" || *actions[1].Height != "7" || *actions[1].Round != "2" || actions[5].Event != "STATE" {
		t.Fatal(actions)
	}
	unknown, err := timedActions([]consensus.Output{consensus.Relay{}}, types.Address{})
	if err != nil || unknown[0].RecipientEvidence != "unknown" || unknown[0].EligibleRecipients == nil {
		t.Fatal("unknown targets treated as observed empty delivery", unknown, err)
	}
	empty, err := timedActions(nil, types.Address{})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty output list unknown")
	}
}
