package validator

// IntegerQuorumSize returns floor(2*n/3)+1 for a nonnegative committee size.
// The subtraction form avoids overflow at the largest representable size.
// The empty committee retains a quorum of one.
func IntegerQuorumSize(n int) int {
	if n <= 0 {
		return 1
	}
	return n - (n-1)/3
}
