// A fixture, not real code. It exists so the no-runtime-skip scanner can be
// SHOWN to fire; a scanner that has never once fired is a scanner nobody knows
// is wired up.
//
// There is one function per (receiver, method) pair the scanner recognizes, so
// dropping any single entry from skipMethods or skipReceivers fails the golden
// test. A fixture with several violations and a test asserting only "something
// was found" would pass on the strength of the others — measured: removing
// "Skip" from skipMethods left the first version of that test green.
//
// It is not a _test.go file on purpose: the scanner must find a skip wherever
// it is, and naming it _test.go inside testdata would make it look like a test
// the go tool ought to run.

package dirty

import "testing"

func FixtureSkips(t *testing.T) {
	if somethingMissing() {
		t.Skip("this reports success without running")
	}
}

func FixtureSkipf(t *testing.T) {
	t.Skipf("also a skip, with %s", "formatting")
}

func FixtureSkipNow(t *testing.T) {
	t.SkipNow()
}

func FixtureShort(t *testing.T) {
	if testing.Short() {
		t.Log("gated on a flag")
	}
}

func FixtureBenchSkip(b *testing.B) {
	b.Skip("benchmarks count too")
}

func FixtureFuzzSkip(f *testing.F) {
	f.Skip("fuzz targets count too")
}

func FixtureTBSkip(tb testing.TB) {
	tb.Skip("a testing.TB handle counts too")
}

func somethingMissing() bool { return true }
