// A fixture proving the no-runtime-skip scanner does NOT fire on the things
// that merely mention a skip. All three shapes below appear in real code in
// this repository, and a textual scanner would report every one of them.

package clean

import "testing"

// FixtureParallel uses t.Parallel, which changes WHEN a test runs and not
// whether it runs. It is not a skip and must not be reported.
func FixtureParallel(t *testing.T) {
	t.Parallel()
}

// FixtureMentionsSkipInProse talks about t.Skip and testing.Short() in a
// comment, the way the convention documents and this package's own
// documentation do.
func FixtureMentionsSkipInProse(t *testing.T) {
	// A t.Skip here would report success without running, so there is not one.
	message := "t.Skip( and testing.Short() inside a string literal"
	_ = message
	t.Log(message)
}

// FixtureOtherSkip calls Skip on something that is not a testing handle.
func FixtureOtherSkip(t *testing.T) {
	decoder := fixtureDecoder{}
	decoder.Skip(4)
	t.Log("a decoder's Skip is not a test skip")
}

type fixtureDecoder struct{}

func (fixtureDecoder) Skip(int) {}
