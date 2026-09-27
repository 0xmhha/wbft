// Package header builds the consensus fields of proposal headers, writes and
// merges seals, and verifies proposals and headers in the fixed order of the
// specification. It also verifies header batches, provides light verification
// and the randao mix, and exposes the gas tip comparison. It does not import
// the consensus or node packages, so it can be used as a stand-alone light
// verifier.
package header
