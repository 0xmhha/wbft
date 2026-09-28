package types

type Height struct{ v uint64 }

func (h Height) RefLow64() uint64   { return h.v }
func (h Height) RefLowInt64() int64 { return int64(h.v) }
func (h Height) String() string     { return "" }

type Round struct{ v uint64 }

func (r Round) RefLow64() uint64 { return r.v }
func (r Round) RefLow32() uint32 { return uint32(r.v) }

// Uses inside package types are not checked.
func use(h Height) uint64 { return h.RefLow64() }
