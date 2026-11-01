package zdas

import "time"

// Exports for the external zdas_test package, which runs the zdastest
// conformance suite and so cannot live in package zdas without an import
// cycle.

// NewMemoryStoreForTest returns the in-memory default Store, as NewServer
// builds it, along with a func that stops its cleanup goroutine.
func NewMemoryStoreForTest(sessionTTL, codeTTL time.Duration) (Store, func()) {
	s := newMemStore(sessionTTL, codeTTL, storeSweepInterval)
	return s, s.stop
}

// NewJSONStoreForTest returns the JSON-serializing test Store from
// store_test.go, so the conformance suite is checked against a store that
// behaves like an external database as well as against the default.
func NewJSONStoreForTest() Store {
	return newJSONStore()
}
