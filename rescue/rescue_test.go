package rescue

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/stretchr/testify/require"
)

// loadTestDB reads the canned channel.db fixture from disk for use in tests.
func loadTestDB(t *testing.T) []byte {
	t.Helper()
	path := testDBPath(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "loadTestDB read test db")
	return data
}

// testDBPath returns the absolute path to the test channel.db file.
func testDBPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "testDBPath determine caller")

	return filepath.Clean(
		filepath.Join(filepath.Dir(file), "..", "cmd", "chantools", "testdata", "channel.db"),
	)
}

// rescueAll is a helper that runs RescueChannels and fails the test on error.
func rescueAll(t *testing.T, data []byte) []*channeldb.OpenChannel {
	t.Helper()
	chans, err := RescueChannels(bytes.NewReader(data))
	require.NoError(t, err, "rescueAll call rescue")
	return chans
}

// channelMap makes it easy to look up channels by their funding outpoint.
func channelMap(chans []*channeldb.OpenChannel) map[string]*channeldb.OpenChannel {
	out := make(map[string]*channeldb.OpenChannel)
	for _, c := range chans {
		out[c.FundingOutpoint.String()] = c
	}
	return out
}

// TestRescueChannelsFromCorruptedFile asserts that RescueChannels can rebuild
// every entry even when the beginning of the DB file is clobbered.
func TestRescueChannelsFromCorruptedFile(t *testing.T) {
	req := require.New(t)

	clean := loadTestDB(t)
	baseline := rescueAll(t, clean)
	req.NotEmpty(baseline, "expected channels from clean db")
	baseMap := channelMap(baseline)

	corrupted := make([]byte, len(clean))
	copy(corrupted, clean)
	for i := 0; i < 8192 && i < len(corrupted); i++ {
		corrupted[i] = 0
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "channel.db")
	req.NoError(os.WriteFile(path, corrupted, 0o600),
		"TestRescueChannelsFromCorruptedFile write corrupt db")
	_, _, err := lnd.OpenDB(path, true)
	req.Error(err, "expected corrupted db to fail opening")

	rescued := rescueAll(t, corrupted)
	req.Equal(len(baseline), len(rescued),
		"TestRescueChannelsFromCorruptedFile rescued count")

	for _, ch := range rescued {
		base, ok := baseMap[ch.FundingOutpoint.String()]
		req.True(ok, "unexpected channel %s", ch.FundingOutpoint)
		req.Equal(base.Capacity, ch.Capacity, "capacity mismatch %s", ch.FundingOutpoint)
		req.NotNil(ch.LocalCommitment.CommitTx, "missing commitment %s", ch.FundingOutpoint)
		req.NotNil(base.LocalCommitment.CommitTx, "baseline missing commitment %s", ch.FundingOutpoint)
		req.Equal(base.LocalCommitment.CommitTx.TxHash(), ch.LocalCommitment.CommitTx.TxHash())
		req.True(locatorsEqual(ch.RevocationKeyLocator, base.RevocationKeyLocator), "revocation locator mismatch %s", ch.FundingOutpoint)
		req.True(pubKeyEqual(ch.RemoteCurrentRevocation, base.RemoteCurrentRevocation), "remote current revocation mismatch %s", ch.FundingOutpoint)
		req.True(pubKeyEqual(ch.RemoteNextRevocation, base.RemoteNextRevocation), "remote next revocation mismatch %s", ch.FundingOutpoint)
		req.True(bytes.Equal(producerBytes(t, ch.RevocationProducer), producerBytes(t, base.RevocationProducer)), "revocation producer mismatch %s", ch.FundingOutpoint)
		req.True(bytes.Equal(storeBytes(t, ch.RevocationStore), storeBytes(t, base.RevocationStore)), "revocation store mismatch %s", ch.FundingOutpoint)
	}
}

// TestLoadChannels covers both the normal channeldb load path and the rescue
// fallback when the file cannot be opened.
func TestLoadChannels(t *testing.T) {
	req := require.New(t)

	clean := loadTestDB(t)
	dir := t.TempDir()

	cleanPath := filepath.Join(dir, "clean.db")
	req.NoError(os.WriteFile(cleanPath, clean, 0o600),
		"TestLoadChannels write clean copy")

	chans, err := LoadChannels(cleanPath, false)
	req.NoError(err, "expected channels from clean db")
	req.NotEmpty(chans, "TestLoadChannels clean fetch")

	rescuedClean, err := LoadChannels(cleanPath, true)
	req.NoError(err, "TestLoadChannels rescue clean")
	req.Len(rescuedClean, len(chans), "TestLoadChannels rescue size")

	corrupted := make([]byte, len(clean))
	copy(corrupted, clean)
	for i := 0; i < 8192 && i < len(corrupted); i++ {
		corrupted[i] = 0
	}

	corruptPath := filepath.Join(dir, "corrupt.db")
	req.NoError(os.WriteFile(corruptPath, corrupted, 0o600),
		"TestLoadChannels write corrupt copy")
	_, err = LoadChannels(corruptPath, false)
	req.Error(err, "expected error without rescue")

	rescued, err := LoadChannels(corruptPath, true)
	req.NoError(err, "TestLoadChannels rescue corrupt")
	req.NotEmpty(rescued, "expected rescued channels")
}

// TestParseChanInfoAndCommit ensures we can parse the chan-info and commitment
// payloads at a given offset without error.
func TestParseChanInfoAndCommit(t *testing.T) {
	req := require.New(t)

	data := loadTestDB(t)
	offsets := findKeyOffsets(data, []byte(infoKey))
	req.NotEmpty(offsets, "no chan-info-key entries found")
	keyOffset := offsets[0]

	info, err := parseChanInfo(bytes.NewReader(data), keyOffset, keyOffset+int64(len(infoKey)))
	req.NoError(err, "TestParseChanInfoAndCommit parse info")
	req.NotEqual(wire.OutPoint{}, info.outpoint,
		"TestParseChanInfoAndCommit funding outpoint")
	req.NoError(info.populateAuxData(bytes.NewReader(data), keyOffset),
		"TestParseChanInfoAndCommit populate aux")

	commit, err := findCommitment(bytes.NewReader(data), keyOffset)
	req.NoError(err, "TestParseChanInfoAndCommit find commitment")
	req.NotNil(commit.Tx, "TestParseChanInfoAndCommit commitment tx")

	_, err = rescueChannelAtOffset(bytes.NewReader(data), keyOffset)
	req.NoError(err, "TestParseChanInfoAndCommit rescue at offset")
}

// TestParseRevocationState ensures that the revocation state blob is decoded
// into the expected keys, producer, and store.
func TestParseRevocationState(t *testing.T) {
	req := require.New(t)

	priv1, err := btcec.NewPrivateKey()
	req.NoError(err)
	priv2, err := btcec.NewPrivateKey()
	req.NoError(err)

	var root chainhash.Hash
	_, err = rand.Read(root[:])
	req.NoError(err)
	producer := shachain.NewRevocationProducer(root)
	store := shachain.NewRevocationStore()

	secret, err := producer.AtIndex(0)
	req.NoError(err, "TestParseRevocationState producer index")
	req.NoError(store.AddNextEntry(secret),
		"TestParseRevocationState store add entry")

	var buf bytes.Buffer
	req.NoError(channeldb.WriteElements(
		&buf, priv1.PubKey(), producer, store, priv2.PubKey(),
	), "TestParseRevocationState write elements")

	state, err := parseRevocationState(bytes.NewReader(buf.Bytes()), 0)
	req.NoError(err, "TestParseRevocationState parse state")
	req.True(pubKeyEqual(state.remoteCurrent, priv1.PubKey()),
		"TestParseRevocationState remote current")
	req.True(pubKeyEqual(state.remoteNext, priv2.PubKey()),
		"TestParseRevocationState remote next")
	req.True(bytes.Equal(producerBytes(t, state.producer), producerBytes(t, producer)),
		"TestParseRevocationState producer payload")
	req.True(bytes.Equal(storeBytes(t, state.store), storeBytes(t, store)),
		"TestParseRevocationState store payload")
}

func findKeyOffsets(data []byte, key []byte) []int64 {
	var offsets []int64
	searchFrom := 0
	for {
		idx := bytes.Index(data[searchFrom:], key)
		if idx == -1 {
			break
		}
		offsets = append(offsets, int64(searchFrom+idx))
		searchFrom += idx + 1
	}
	return offsets
}

func locatorsEqual(a, b keychain.KeyLocator) bool {
	return a.Family == b.Family && a.Index == b.Index
}

func pubKeyEqual(a, b *btcec.PublicKey) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.IsEqual(b)
	}
}

func producerBytes(t *testing.T, p shachain.Producer) []byte {
	t.Helper()
	if p == nil {
		return nil
	}
	var buf bytes.Buffer
	require.NoError(t, p.Encode(&buf), "producerBytes encode producer")
	return buf.Bytes()
}

func storeBytes(t *testing.T, s shachain.Store) []byte {
	t.Helper()
	if s == nil {
		return nil
	}
	var buf bytes.Buffer
	require.NoError(t, s.Encode(&buf), "storeBytes encode store")
	return buf.Bytes()
}
