package window

func impure(m map[string]int) {
	for range m { // want "range over a map"
	}
	go func() {}() // want "go statement"
	var c chan int // want "channel type"
	_ = c
}
