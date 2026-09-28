package header

import "github.com/0xmhha/wbft/types"

func ok(h types.Height, r types.Round) {
	_ = h.RefLow64() //wbft:low64 HH-20
	//wbft:low64 HH-21 the parent lookup
	_ = h.RefLow64()
	_ = r.RefLow32() //wbft:low64 HH-74
	_ = h.String()
}

func bad(h types.Height, r types.Round) {
	_ = h.RefLow64()    // want `RefLow64 without //wbft:low64 HH-nn`
	_ = h.RefLowInt64() //wbft:low64 HH-99 // want `names unknown label HH-99`
	_ = r.RefLow64()    //wbft:low64 // want `names unknown label`
	f := h.RefLow64     // want `RefLow64 without`
	_ = f
}
