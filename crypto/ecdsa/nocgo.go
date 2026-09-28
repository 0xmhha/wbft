//go:build !cgo

package ecdsa

// wbft is built with cgo only: the reference accepts signatures with the
// rules of its cgo build of libsecp256k1, and the no-cgo recovery of
// go-ethereum accepts recovery bytes that the cgo build rejects. This
// declaration stops a build without cgo.
var _ = cgoIsRequiredToBuildWbft
