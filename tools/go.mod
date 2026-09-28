module github.com/0xmhha/wbft/tools

go 1.25.0

require golang.org/x/tools v0.49.0

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/ethereum/go-ethereum v1.17.4 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

require (
	github.com/0xmhha/wbft v0.0.0
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
)

replace github.com/0xmhha/wbft => ../
