// Package event defines the vocabulary of consensus events and a writer of
// the JSON Lines event stream. The core and the transport emit Record values
// without depending on any sink; the node or a simulator stamps them with the
// common fields and writes them one per line.
package event
