package header

// VerifyHeaders may verify headers in parallel.
func VerifyHeaders(n int) <-chan error {
	out := make(chan error, n)
	go func() {
		for i := 0; i < n; i++ {
			out <- nil
		}
		close(out)
	}()
	return out
}

func verifyOne(results chan error) { // want `channel type`
	go func() {}() // want `go statement`
}
