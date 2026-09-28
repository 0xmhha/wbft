package consensus

// Test files are not checked.
func helper(m map[int]int) {
	go func() {}()
	for range m {
	}
}
