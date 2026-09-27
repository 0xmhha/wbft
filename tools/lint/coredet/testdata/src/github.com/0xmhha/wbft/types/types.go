package types

func Keys(m map[string]bool) int {
	n := 0
	for k := range m { // want `range over a map without`
		n += len(k)
	}
	return n
}

func Wait(c chan int) { // want `channel type`
	<-c // want `channel receive`
}
