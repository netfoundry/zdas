package zdas_test

import (
	"testing"
	"time"

	"github.com/netfoundry/zdas/pkg/zdas"
	"github.com/netfoundry/zdas/pkg/zdas/zdastest"
)

func TestMemoryStoreConformance(t *testing.T) {
	zdastest.TestStore(t, func(t *testing.T) zdas.Store {
		s, stop := zdas.NewMemoryStoreForTest(10*time.Minute, 60*time.Second)
		t.Cleanup(stop)
		return s
	})
}

func TestJSONStoreConformance(t *testing.T) {
	zdastest.TestStore(t, func(*testing.T) zdas.Store {
		return zdas.NewJSONStoreForTest()
	})
}
