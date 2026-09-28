package types

// ChainReader is the application's read-only view of its chain. Number
// arguments are canonical indices: the low 64 bits of Header.Number, the key
// under which the application stores headers.
type ChainReader interface {
	// Head returns the current canonical head.
	Head() *Header
	// HeaderByNumber returns the canonical header at idx, or nil.
	HeaderByNumber(idx uint64) *Header
	// Header returns the stored header with that hash whose index is idx, or
	// nil. It finds non-canonical headers as well.
	Header(hash Hash, idx uint64) *Header
	// HeaderByHash returns the stored header with that hash, or nil.
	HeaderByHash(hash Hash) *Header
	// HasBlock reports whether the block with that hash and index is stored.
	HasBlock(hash Hash, idx uint64) bool
}
