package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// A few cases of the specification's worked examples, answered through the
// protocol as the runner would send them.
func TestHandlerExamples(t *testing.T) {
	tests := []struct {
		handler string
		input   string
		output  string // empty: the case must fail
	}{
		{"crypto/keccak256", `{"data":"0x77626674"}`, `{"hash":"0x154d94908e42308ff21897b1445bd5001dedb9fa41095ad342cb656fffe2c55f"}`},
		{"crypto/randao_data", `{"chain_id":"8282","number":"1"}`, `{"randao_data":"0x48516c21b70c7a85c71e6fe34cd724419d7803fb58bc1cf3f69a76eb85d98b3f"}`},
		{"validators/quorum", `{"n":"4"}`, `{"f_float64_bits":"0x3ff0000000000000","quorum":"3","f_plus_one":"2"}`},
		{"validators/proposer", `{"validators":[],"policy":"0","last_proposer":"0x0000000000000000000000000000000000001001","round":"0"}`, `{"index":null,"address":null}`},
		{"validators/sort_candidates", `{"diligences":["5","7","5","7","5","7","5","7","5","7","5","7","5","7","5"]}`,
			`{"order":["9","7","13","3","11","5","1","8","6","0","10","4","12","2","14"]}`},
		{"validators/shuffle", `{"seed":"0x0000000000000000000000000000000000000000000000000000000000000000","count":"4","indices":["0","1","2","3"]}`,
			`{"shuffled":["2","3","0","1"]}`},
		{"validators/shuffle", `{"seed":"0x0000000000000000000000000000000000000000000000000000000000000000","count":"4","indices":["4"]}`, ""},
		{"timers/round_timeout", `{"request_timeout":"2000","max_request_timeout_seconds":"0","round":"33"}`, `{"timeout":"9223372036854775807","warning":"max_int64_clamp"}`},
		{"encoding/extra_codec", `{"extra":"0xca808080c0c080c0c080c0"}`,
			`{"vanity_data":"0x","randao_reveal":"0x","prev_round":"0","prev_prepared_seal":null,"prev_committed_seal":null,"round":"0","prepared_seal":null,"committed_seal":null,"gas_tip":"0","epoch_info":null,"encoded":"0xca808080c0c080c0c080c0"}`},
		{"encoding/extra_codec", `{"extra":"0xca808080808080c0c080c0"}`, ""},
		{"encoding/message_codec", `{"code":"17","payload":"0xc0"}`, ""},
		{"chain/config_at", `{"config":{"wbft":{"request_timeout_seconds":"2","block_period_seconds":"1","epoch_length":"10","allowed_future_block_time":"0","proposer_policy":"0","max_request_timeout_seconds":null},"transitions":[]},"number":"5"}`,
			`{"request_timeout":"2000","block_period":"1","epoch":"10","proposer_policy":"0","max_request_timeout_seconds":"0","allowed_future_block_time":"0"}`},
		{"validators/epoch_boundary", `{"config":{"wbft":{"request_timeout_seconds":"2","block_period_seconds":"1","epoch_length":"10","allowed_future_block_time":"0","proposer_policy":"0","max_request_timeout_seconds":null},"transitions":[]},"number":"25"}`,
			`{"is_epoch_block":false,"last_epoch_block":"20"}`},
		{"state_machine/check_message", `{"view":{"sequence":"10","round":"2"},"state":"AcceptRequest","prior_round":"1","code":"20","message_view":{"sequence":"9","round":"1"}}`, `{"result":"EXTRA_SEAL"}`},
		{"state_machine/check_message", `{"view":{"sequence":"10","round":"2"},"state":"Busy","prior_round":"1","code":"20","message_view":{"sequence":"9","round":"1"}}`, ""},
		{"state_machine/is_justified", `{"proposal":"0x0000000000000000000000000000000000000000000000000000000000000001","target_view":{"sequence":"10","round":"1"},"round_changes":[],"prepares":[],"quorum":"3"}`, `{"justified":false}`},
		{"timers/build_wait", `{"block_period":"1","head_time":"1700000000","round":"0","now":"1700000000250000000"}`, `{"wait":"750000000"}`},
		{"timers/build_wait", `{"block_period":"1","head_time":"1700000000","round":"1","now":"1700000000250000000"}`, `{"wait":"0"}`},
		// An unknown input field is a malformed case, not a silent pass.
		{"crypto/keccak256", `{"data":"0x","extra":"0x"}`, ""},
	}
	for _, tt := range tests {
		r, h, _ := strings.Cut(tt.handler, "/")
		_, msgs, _ := session(t, runnerHello,
			`{"type":"case","id":1,"runner":"`+r+`","handler":"`+h+`","case":"c","kind":"pure","input":`+tt.input+`}`,
			`{"type":"bye"}`)
		if len(msgs) != 2 {
			t.Fatalf("%s: %d messages", tt.handler, len(msgs))
		}
		res := msgs[1]
		if tt.output == "" {
			if res["status"] != "error" {
				t.Errorf("%s %s: status %v, want error", tt.handler, tt.input, res["status"])
			}
			continue
		}
		var want map[string]any
		if err := json.Unmarshal([]byte(tt.output), &want); err != nil {
			t.Fatal(err)
		}
		if res["status"] != "ok" || !reflect.DeepEqual(res["output"], want) {
			t.Errorf("%s %s: %v", tt.handler, tt.input, res)
		}
	}
}
