package main

import "math/big"

// defaultRPC is the public JSON-RPC endpoint of the StableNet testnet.
const defaultRPC = "https://api.test.stablenet.network"

// preset is the part of a network preset the scanner needs.
type preset struct {
	config      string   // genesis "config" object (consensus part)
	forks       []uint64 // fork blocks; forks at block 0 are not scanned separately
	london      *big.Int // London block (execution-side header steps)
	genesisHash string   // expected genesis hash, empty to skip the check
}

// testnetPreset is the StableNet testnet preset of go-stablenet
// (params/config.go, network id 8283): every Ethereum fork up to London and
// Applepie at block 0, Boho at block 14 408 500, no transitions.
var testnetPreset = preset{
	config: `{
  "chainId": 8283,
  "anzeon": {
    "wbft": {"requestTimeoutSeconds": 2, "blockPeriodSeconds": 1, "epochLength": 140, "proposerPolicy": 0},
    "init": {
      "validators": [
        "0x9f06600b2c17108662e3840e76bb27c9468eb73d",
        "0x1aa18ec0b3131171b1b1ddba2dffd81410b30a5a",
        "0xe63b413353e1ba4ac99f2bd1892328e2365ec574",
        "0x20f681210071932dbe6387378adf6f26af029f7d",
        "0x5803c14973690550d6ffc2014b7bffd8005f6021",
        "0x59f6e6add1fbeab316a7b17c9f1966b3655efedb",
        "0x0a8dd92ce7ce53bbf6aed40228f9029bb3f92702"
      ],
      "blsPublicKeys": [
        "0x96683524c3b7e224f2146a0dbb87593e3dee21b7d97c1b24ef6ed799c977be40d3dff8e45b7fcdb48f7713095d84dd9c",
        "0x80bd166ebfdb29553801dc22f5b83534945cc2a6dacf39d422383cb3041c8afab8cd430ffc29e9297ba2e114efae487f",
        "0xa418ff21040af17cb3f5109fa075c92d771e508e715230413d6548d54114666011b715d2e60dfd4e20661d5327b67d6d",
        "0xa529026635cf95fd84a9633c62bedaf2a5999f2d5542164086176e24b0c2256a3daa7b76344b631c0bd344895b3f44b9",
        "0xb2aa67ceb23d96e4de5dca871dfbda6ba122a3b5a55b3a00547fdda906ab8e4892e98de4b36b541088ac8ff6de7d6a35",
        "0x88717d8edbabaf65015b656b5a14bc27705bead8a75f81b9bc064b69b7a5e8f5a010d54cdb85b5b3cab16ce5d816062f",
        "0x86949700dc2722f48cd649af74cff788bf17553d19278592ca7be54929d1646d60efd1ea12f9dabd7d0143d9813bfea8"
      ]
    }
  }
}`,
	forks:       []uint64{0 /* Ethereum forks .. London, Applepie */, 14_408_500 /* Boho */},
	london:      big.NewInt(0),
	genesisHash: "0x2bdf79b3d3cc49f9e6638ff81f3bb85065c79945a8fe4556cd0ff47bbfc02490",
}
