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
)

// loadTestDB reads the canned channel.db fixture from disk for use in tests.
func loadTestDB(t *testing.T) []byte {
	t.Helper()
	path := testDBPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test db: %v", err)
	}
	return data
}

// testDBPath returns the absolute path to the test channel.db file.
func testDBPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller")
	}

	return filepath.Clean(
		filepath.Join(filepath.Dir(file), "..", "cmd", "chantools", "testdata", "channel.db"),
	)
}

// rescueAll is a helper that runs RescueChannels and fails the test on error.
func rescueAll(t *testing.T, data []byte) []*channeldb.OpenChannel {
	t.Helper()
	chans, err := RescueChannels(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("rescue channels: %v", err)
	}
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
	clean := loadTestDB(t)
	baseline := rescueAll(t, clean)
	if len(baseline) == 0 {
		t.Fatal("expected channels from clean db")
	}
	baseMap := channelMap(baseline)

	corrupted := make([]byte, len(clean))
	copy(corrupted, clean)
	for i := 0; i < 8192 && i < len(corrupted); i++ {
		corrupted[i] = 0
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "channel.db")
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatalf("write temp db: %v", err)
	}
	if _, _, err := lnd.OpenDB(path, true); err == nil {
		t.Fatal("expected corrupted db to fail opening")
	}

	rescued := rescueAll(t, corrupted)
	if len(rescued) != len(baseline) {
		t.Fatalf("expected %d channels, got %d", len(baseline), len(rescued))
	}

	for _, ch := range rescued {
		base, ok := baseMap[ch.FundingOutpoint.String()]
		if !ok {
			t.Fatalf("unexpected channel %s", ch.FundingOutpoint)
		}
		if ch.Capacity != base.Capacity {
			t.Fatalf("capacity mismatch for %s", ch.FundingOutpoint)
		}
		if ch.LocalCommitment.CommitTx == nil {
			t.Fatalf("missing commitment for %s", ch.FundingOutpoint)
		}
		if base.LocalCommitment.CommitTx == nil {
			t.Fatalf("baseline missing commit for %s", ch.FundingOutpoint)
		}
		if ch.LocalCommitment.CommitTx.TxHash() != base.LocalCommitment.CommitTx.TxHash() {
			t.Fatalf("commit tx mismatch for %s", ch.FundingOutpoint)
		}
		if !locatorsEqual(ch.RevocationKeyLocator, base.RevocationKeyLocator) {
			t.Fatalf("revocation locator mismatch for %s", ch.FundingOutpoint)
		}
		if !pubKeyEqual(ch.RemoteCurrentRevocation, base.RemoteCurrentRevocation) {
			t.Fatalf("remote current revocation mismatch for %s", ch.FundingOutpoint)
		}
		if !pubKeyEqual(ch.RemoteNextRevocation, base.RemoteNextRevocation) {
			t.Fatalf("remote next revocation mismatch for %s", ch.FundingOutpoint)
		}
		if !bytes.Equal(producerBytes(t, ch.RevocationProducer), producerBytes(t, base.RevocationProducer)) {
			t.Fatalf("revocation producer mismatch for %s", ch.FundingOutpoint)
		}
		if !bytes.Equal(storeBytes(t, ch.RevocationStore), storeBytes(t, base.RevocationStore)) {
			t.Fatalf("revocation store mismatch for %s", ch.FundingOutpoint)
		}
	}
}

// TestLoadChannels covers both the normal channeldb load path and the rescue
// fallback when the file cannot be opened.
func TestLoadChannels(t *testing.T) {
	clean := loadTestDB(t)
	dir := t.TempDir()

	cleanPath := filepath.Join(dir, "clean.db")
	if err := os.WriteFile(cleanPath, clean, 0o600); err != nil {
		t.Fatalf("write clean copy: %v", err)
	}

	chans, err := LoadChannels(cleanPath, false)
	if err != nil {
		t.Fatalf("load clean channels: %v", err)
	}
	if len(chans) == 0 {
		t.Fatal("expected channels from clean db")
	}

	rescuedClean, err := LoadChannels(cleanPath, true)
	if err != nil {
		t.Fatalf("load clean channels with rescue: %v", err)
	}
	if len(rescuedClean) != len(chans) {
		t.Fatalf("expected %d rescued clean channels, got %d",
			len(chans), len(rescuedClean))
	}

	corrupted := make([]byte, len(clean))
	copy(corrupted, clean)
	for i := 0; i < 8192 && i < len(corrupted); i++ {
		corrupted[i] = 0
	}

	corruptPath := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(corruptPath, corrupted, 0o600); err != nil {
		t.Fatalf("write corrupt copy: %v", err)
	}
	if _, err := LoadChannels(corruptPath, false); err == nil {
		t.Fatal("expected error without rescue")
	}

	rescued, err := LoadChannels(corruptPath, true)
	if err != nil {
		t.Fatalf("load channels with rescue: %v", err)
	}
	if len(rescued) == 0 {
		t.Fatal("expected rescued channels")
	}
}

// TestParseChanInfoAndCommit ensures we can parse the chan-info and commitment
// payloads at a given offset without error.
func TestParseChanInfoAndCommit(t *testing.T) {
	data := loadTestDB(t)
	offsets := findKeyOffsets(data, []byte(infoKey))
	if len(offsets) == 0 {
		t.Fatal("no chan-info-key entries found")
	}
	keyOffset := offsets[0]

	info, err := parseChanInfo(bytes.NewReader(data), keyOffset, keyOffset+int64(len(infoKey)))
	if err != nil {
		t.Fatalf("parse channel info: %v", err)
	}

	if (info.outpoint == wire.OutPoint{}) {
		t.Fatalf("expected funding outpoint, got zero")
	}

	if err := info.populateAuxData(bytes.NewReader(data), keyOffset); err != nil {
		t.Fatalf("populate aux data: %v", err)
	}

	commit, err := findCommitment(bytes.NewReader(data), keyOffset)
	if err != nil {
		t.Fatalf("find commitment: %v", err)
	}
	if commit.Tx == nil {
		t.Fatal("expected commitment tx")
	}

	if _, err := rescueChannelAtOffset(bytes.NewReader(data), keyOffset); err != nil {
		t.Fatalf("rescue at offset: %v", err)
	}
}

// TestParseRevocationState ensures that the revocation state blob is decoded
// into the expected keys, producer, and store.
func TestParseRevocationState(t *testing.T) {
	priv1, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("priv1: %v", err)
	}
	priv2, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("priv2: %v", err)
	}

	var root chainhash.Hash
	if _, err := rand.Read(root[:]); err != nil {
		t.Fatalf("rand root: %v", err)
	}
	producer := shachain.NewRevocationProducer(root)
	store := shachain.NewRevocationStore()

	secret, err := producer.AtIndex(0)
	if err != nil {
		t.Fatalf("producer at index: %v", err)
	}
	if err := store.AddNextEntry(secret); err != nil {
		t.Fatalf("store add: %v", err)
	}

	var buf bytes.Buffer
	if err := channeldb.WriteElements(
		&buf, priv1.PubKey(), producer, store, priv2.PubKey(),
	); err != nil {
		t.Fatalf("write rev state: %v", err)
	}

	state, err := parseRevocationState(bytes.NewReader(buf.Bytes()), 0)
	if err != nil {
		t.Fatalf("parse revocation state: %v", err)
	}
	if !pubKeyEqual(state.remoteCurrent, priv1.PubKey()) {
		t.Fatal("unexpected current revocation")
	}
	if !pubKeyEqual(state.remoteNext, priv2.PubKey()) {
		t.Fatal("unexpected next revocation")
	}
	if !bytes.Equal(producerBytes(t, state.producer), producerBytes(t, producer)) {
		t.Fatal("unexpected producer payload")
	}
	if !bytes.Equal(storeBytes(t, state.store), storeBytes(t, store)) {
		t.Fatal("unexpected store payload")
	}
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
	if err := p.Encode(&buf); err != nil {
		t.Fatalf("encode producer: %v", err)
	}
	return buf.Bytes()
}

func storeBytes(t *testing.T, s shachain.Store) []byte {
	t.Helper()
	if s == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := s.Encode(&buf); err != nil {
		t.Fatalf("encode store: %v", err)
	}
	return buf.Bytes()
}
