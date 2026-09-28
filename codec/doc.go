// Package codec encodes and decodes the WBFT extra data, headers, blocks and
// the four consensus messages. It also computes the signing payloads, the
// header hashes (filtered header, hash with round, block hash), the seal and
// randao data, and the deduplication key of a message.
package codec
