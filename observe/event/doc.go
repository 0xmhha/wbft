// Package event defines the vocabulary of consensus events and a writer of
// the JSON Lines event stream. The core and the transport emit Record values
// without depending on any sink; the node or a simulator stamps them with the
// common fields and writes them one per line. The records are described by
// the schema file schema/events-v1.json (package schema), which tools that
// do not import Go read.
package event
