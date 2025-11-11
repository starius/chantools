package rescue

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"unsafe"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
)

var (
	// errChannelNotFound signals that no chan-info-key entries were found.
	errChannelNotFound = errors.New("no channels rescued")

	// errRevocationNotFound indicates the revocation blob is missing near
	// a chan-info-key entry.
	errRevocationNotFound = errors.New("revocation state not found")
)

const (
	// infoKey is the Bolt bucket key that stores the static channel header.
	infoKey = "chan-info-key"

	// commitKey is the Bolt key that stores commitment snapshots.
	commitKey = "chan-commitment-key"

	// chunkSize controls how many bytes are scanned at once while looking
	// for chan-info-key occurrences.
	chunkSize = 4 << 20

	// commitSearchRadius is the byte distance to scan around a chan-info
	// hit to locate adjacent commitment or revocation blobs.
	commitSearchRadius = 1 << 15

	// siblingSearchRadius bounds the window when looking for nearby keys
	// such as frozen-chans.
	siblingSearchRadius = 4 << 10

	// headerReadLimit caps how many bytes are read when decoding the
	// chan-info payload.
	headerReadLimit = 1 << 20

	// commitmentReadLimit caps how many bytes are read when decoding the
	// commitment payload.
	commitmentReadLimit = 1 << 20

	// commitSigMaxSize mirrors the maximum variable length signature size
	// accepted by channeldb when encoding commitments.
	commitSigMaxSize = 66000
)

// open channel auxiliary TLV types copied from lnd/channeldb/channel.go.
const (
	openChanTlvTypeRevokeKeyLoc         = 1
	openChanTlvTypeInitialLocalBalance  = 2
	openChanTlvTypeInitialRemoteBalance = 3
	openChanTlvTypeRealScid             = 4
	openChanTlvTypeMemo                 = 5
	openChanTlvTypeTapscriptRoot        = 6
	openChanTlvTypeCustomBlob           = 7
	openChanTlvTypeConfirmationHeight   = 8

	// openChanAuxMaxType is the highest TLV type we currently expect.
	openChanAuxMaxType = openChanTlvTypeConfirmationHeight
)

// RescueChannels scans a raw channel.db byte stream and rebuilds every entry
// that still lives in LND's open-channel bucket. This includes:
//   - Pending-open channels (funding TX not yet confirmed)
//   - Fully open/active channels
//   - Channels whose closing transaction has been broadcast but not fully
//     settled yet (aka "waiting close", represented in LND by chanStatus flags)
//
// Channels that have already been moved to the closed/historical buckets are
// not surfaced, because their metadata is stored elsewhere in channel.db.
// The reader must implement io.ReaderAt so random access near rescued keys
// is possible.
func RescueChannels(r io.ReaderAt) ([]*channeldb.OpenChannel, error) {
	matches, err := scanForChannels(r)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, errChannelNotFound
	}
	return matches, nil
}

// LoadChannels attempts to read all open channels from the given channel DB
// path. It always tries to open the Bolt database first. When useRescue is
// true, it falls back to rescanning the raw DB if the Bolt open fails, the
// fetch errors, or zero channels are returned.
func LoadChannels(dbPath string, useRescue bool) ([]*channeldb.OpenChannel, error) {
	channelDB, _, err := lnd.OpenDB(dbPath, true)
	if err == nil {
		channels, fetchErr := channelDB.ChannelStateDB().FetchAllChannels()
		_ = channelDB.Close()

		switch {
		case fetchErr != nil:
			if !useRescue {
				return nil, fetchErr
			}

		case len(channels) > 0:
			return channels, nil

		default:
			if !useRescue {
				return channels, nil
			}
		}
	} else if !useRescue {
		return nil, fmt.Errorf("error opening channel DB: %w", err)
	}

	return loadChannelsFromRaw(dbPath)
}

// setChannelStatus mutates the private chanStatus field on channeldb.OpenChannel
// using reflection+unsafe so rescued channels retain their waiting-close
// metadata for in-memory filtering. This avoids the need for a live DB handle.
func setChannelStatus(channel *channeldb.OpenChannel, status channeldb.ChannelStatus) {
	if channel == nil {
		return
	}

	field := reflect.ValueOf(channel).Elem().FieldByName("chanStatus")
	if !field.IsValid() {
		return
	}

	ptr := unsafe.Pointer(field.UnsafeAddr())
	typed := (*channeldb.ChannelStatus)(ptr)
	*typed = status
}

// loadChannelsFromRaw opens the DB file and runs the raw rescue pipeline.
func loadChannelsFromRaw(dbPath string) ([]*channeldb.OpenChannel, error) {
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening channel DB for rescue: %w",
			err)
	}
	defer func() {
		_ = file.Close()
	}()

	return RescueChannels(file)
}

// scanForChannels iterates over the raw DB bytes by sliding a fixed-size
// window, looking for occurrences of chan-info-key, and attempts to hydrate
// OpenChannel instances from each hit.
func scanForChannels(r io.ReaderAt) ([]*channeldb.OpenChannel, error) {
	key := []byte(infoKey)
	buf := make([]byte, chunkSize+len(key)-1)
	tail := make([]byte, len(key)-1)
	tailLen := 0
	var channels []*channeldb.OpenChannel
	var offset int64

	for {
		// Carry the tail bytes from the previous chunk so matches crossing the
		// chunk boundary remain visible in this iteration.
		copy(buf[:tailLen], tail[:tailLen])
		n, err := r.ReadAt(buf[tailLen:tailLen+chunkSize], offset)
		total := tailLen + n

		if total > 0 {
			window := buf[:total]
			base := offset - int64(tailLen)
			searchFrom := 0
			for {
				idx := bytes.Index(window[searchFrom:], key)
				if idx == -1 {
					break
				}

				absolute := base + int64(searchFrom+idx)
				channel, err := rescueChannelAtOffset(r, absolute)
				if err == nil {
					channels = append(channels, channel)
				}

				searchFrom += idx + 1
			}

			if total >= len(key)-1 {
				tailLen = len(key) - 1
				copy(tail[:tailLen], window[total-tailLen:total])
			} else {
				tailLen = total
				copy(tail[:tailLen], window)
			}
			offset += int64(n)
		}

		if err == io.EOF {
			if n == 0 {
				break
			}
		} else if err != nil {
			return nil, err
		}
	}

	return channels, nil
}

// rescueChannelAtOffset parses the chan-info-key payload located at the given
// offset and assembles an OpenChannel instance by pulling in the accompanying
// commitment, revocation, and aux data blobs.
func rescueChannelAtOffset(r io.ReaderAt, keyOffset int64) (*channeldb.OpenChannel, error) {
	dataOffset := keyOffset + int64(len(infoKey))
	info, err := parseChanInfo(r, keyOffset, dataOffset)
	if err != nil {
		return nil, err
	}

	// Attach the commitment state that sits close to the chan-info entry.
	commit, err := findCommitment(r, keyOffset)
	if err != nil {
		return nil, err
	}

	// Decode auxiliary blobs such as revocation state and confirmed SCID.
	if err := info.populateAuxData(r, keyOffset); err != nil {
		return nil, err
	}

	return info.buildChannel(commit), nil
}

// chanInfo mirrors the fixed channel header stored under chan-info-key and
// holds the additional data we glean from nearby blobs.
type chanInfo struct {
	// keyOffset is the byte offset at which chan-info-key was located.
	keyOffset int64

	// dataOffset is the start of the serialized chan-info payload.
	dataOffset int64

	// chanType records the negotiated channel type bits.
	chanType channeldb.ChannelType

	// chainHash identifies the chain the channel belongs to.
	chainHash chainhash.Hash

	// outpoint is the funding outpoint.
	outpoint wire.OutPoint

	// shortID is the alias ShortChannelID stored in the header.
	shortID lnwire.ShortChannelID

	// isPending indicates whether the channel's funding tx is confirmed.
	isPending bool

	// isInitiator records whether we initiated channel funding.
	isInitiator bool

	// status captures ChanStatus bits (waiting close, etc.).
	status channeldb.ChannelStatus

	// fundingHeight is the block height used for the short ID fallback.
	fundingHeight uint32

	// numConfs is the required confirmation count.
	numConfs uint16

	// channelFlags are the lnwire FundingFlags saved during open.
	channelFlags lnwire.FundingFlag

	// remoteIdentity is the remote party's identity pubkey.
	remoteIdentity *btcec.PublicKey

	// capacity is the channel capacity in satoshis.
	capacity btcutil.Amount

	// totalMsatSent tracks historical HTLC volume sent.
	totalMsatSent lnwire.MilliSatoshi

	// totalMsatReceived tracks historical volume received.
	totalMsatReceived lnwire.MilliSatoshi

	// localCfg is our channel configuration.
	localCfg channeldb.ChannelConfig

	// remoteCfg is the peer's channel configuration.
	remoteCfg channeldb.ChannelConfig

	// revocationLocator tells us how to derive the shachain root.
	revocationLocator keychain.KeyLocator

	// confirmedScid carries the confirmed SCID for zero-conf channels.
	confirmedScid lnwire.ShortChannelID

	// hasConfirmed marks whether confirmedScid is populated.
	hasConfirmed bool

	// confirmationHeight stores the block height recorded in aux data.
	confirmationHeight uint32

	// initialLocalBalance is the starting balance we held at open.
	initialLocalBalance lnwire.MilliSatoshi

	// initialRemoteBalance is the peer's starting balance.
	initialRemoteBalance lnwire.MilliSatoshi

	// leaseExpiry holds the CLTV thaw height for leased channels.
	leaseExpiry uint32

	// remoteCurrent is the current revocation public key.
	remoteCurrent *btcec.PublicKey

	// remoteNext is the next revocation public key.
	remoteNext *btcec.PublicKey

	// revocationProd rebuilds the peer's shachain producer.
	revocationProd shachain.Producer

	// revocationStore rebuilds the peer's shachain store.
	revocationStore shachain.Store
}

// commitInfo contains the subset of commitment data needed to rebuild the
// ChannelCommitment struct.
type commitInfo struct {
	// CommitHeight is the per-channel commitment number.
	CommitHeight uint64

	// LocalBalance is the local balance in msat.
	LocalBalance uint64

	// RemoteBalance is the remote balance in msat.
	RemoteBalance uint64

	// CommitFee is the fee in satoshis.
	CommitFee uint64

	// Tx is the raw commitment transaction.
	Tx *wire.MsgTx

	// CommitSig is the remote-signed DER signature for Tx.
	CommitSig []byte
}

// parseChanInfo reads the serialized channel header stored under
// chan-info-key and extracts all static fields needed to build an OpenChannel.
func parseChanInfo(r io.ReaderAt, keyOffset, dataOffset int64) (*chanInfo, error) {
	buf := make([]byte, headerReadLimit)
	n, err := r.ReadAt(buf, dataOffset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	reader := bytes.NewReader(buf[:n])
	info := &chanInfo{
		keyOffset:  keyOffset,
		dataOffset: dataOffset,
	}

	chanTypeVal, err := readVarInt(reader)
	if err != nil {
		return nil, err
	}
	info.chanType = channeldb.ChannelType(chanTypeVal)

	if err := readInto(reader, info.chainHash[:]); err != nil {
		return nil, err
	}
	if err := readInto(reader, info.outpoint.Hash[:]); err != nil {
		return nil, err
	}
	index, err := readUint32(reader)
	if err != nil {
		return nil, err
	}
	info.outpoint.Index = index

	scid, err := readUint64(reader)
	if err != nil {
		return nil, err
	}
	info.shortID = lnwire.NewShortChanIDFromInt(scid)

	if info.isPending, err = readBool(reader); err != nil {
		return nil, err
	}
	if info.isInitiator, err = readBool(reader); err != nil {
		return nil, err
	}

	status, err := readVarInt(reader)
	if err != nil {
		return nil, err
	}
	info.status = channeldb.ChannelStatus(status)

	if info.fundingHeight, err = readUint32(reader); err != nil {
		return nil, err
	}
	if info.numConfs, err = readUint16(reader); err != nil {
		return nil, err
	}

	flagByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	info.channelFlags = lnwire.FundingFlag(flagByte)

	var pubBytes [33]byte
	if err := readInto(reader, pubBytes[:]); err != nil {
		return nil, err
	}
	info.remoteIdentity, err = btcec.ParsePubKey(pubBytes[:])
	if err != nil {
		return nil, err
	}

	amt, err := readUint64(reader)
	if err != nil {
		return nil, err
	}
	info.capacity = btcutil.Amount(amt)

	sent, err := readUint64(reader)
	if err != nil {
		return nil, err
	}
	info.totalMsatSent = lnwire.MilliSatoshi(sent)

	recv, err := readUint64(reader)
	if err != nil {
		return nil, err
	}
	info.totalMsatReceived = lnwire.MilliSatoshi(recv)

	if shouldReadFundingTx(info) {
		// Only single-funder initiators persist the full funding tx. We
		// conditionally deserialize the blob to keep parsing aligned.
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(reader); err != nil {
			return nil, err
		}
	}

	if info.localCfg, err = readChannelConfig(reader); err != nil {
		return nil, err
	}
	if info.remoteCfg, err = readChannelConfig(reader); err != nil {
		return nil, err
	}

	auxBytes := make([]byte, reader.Len())
	if _, err := io.ReadFull(reader, auxBytes); err != nil && err != io.EOF {
		return nil, err
	}
	auxBytes = trimAuxData(auxBytes)
	if len(auxBytes) > 0 {
		if err := info.decodeAuxData(bytes.NewReader(auxBytes)); err != nil {
			return nil, err
		}
	}

	return info, nil
}

// decodeAuxData parses the TLV-encoded auxiliary channel data (revocation key
// locator, initial balances, real SCID, etc.) that lives beyond the fixed
// header. The method only extracts the fields we need for reconstruction.
func (c *chanInfo) decodeAuxData(r *bytes.Reader) error {
	const maxAuxType = 8

	for r.Len() > 0 {
		t, err := readVarInt(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return err
		}
		if t == 0 || t > openChanAuxMaxType {
			break
		}

		l, err := readVarInt(r)
		if err != nil {
			return err
		}
		if l > uint64(r.Len()) {
			return io.ErrUnexpectedEOF
		}

		field := make([]byte, l)
		if _, err := io.ReadFull(r, field); err != nil {
			return err
		}

		switch t {
		case openChanTlvTypeRevokeKeyLoc:
			if len(field) != 8 {
				return fmt.Errorf("unexpected key locator length %d", len(field))
			}
			c.revocationLocator.Family = keychain.KeyFamily(binary.BigEndian.Uint32(field[:4]))
			c.revocationLocator.Index = binary.BigEndian.Uint32(field[4:])

		case openChanTlvTypeInitialLocalBalance:
			if len(field) != 8 {
				return fmt.Errorf("unexpected local balance length %d", len(field))
			}
			c.initialLocalBalance = lnwire.MilliSatoshi(binary.BigEndian.Uint64(field))

		case openChanTlvTypeInitialRemoteBalance:
			if len(field) != 8 {
				return fmt.Errorf("unexpected remote balance length %d", len(field))
			}
			c.initialRemoteBalance = lnwire.MilliSatoshi(binary.BigEndian.Uint64(field))

		case openChanTlvTypeRealScid:
			if len(field) != 8 {
				return fmt.Errorf("unexpected real scid size %d", len(field))
			}
			val := binary.BigEndian.Uint64(field)
			c.confirmedScid = lnwire.NewShortChanIDFromInt(val)
			if c.confirmedScid.BlockHeight != 0 {
				c.hasConfirmed = true
			}

		case openChanTlvTypeConfirmationHeight:
			if len(field) != 4 {
				return fmt.Errorf("unexpected confirmation height len %d", len(field))
			}
			c.confirmationHeight = binary.BigEndian.Uint32(field)

		default:
			// Types 5-7 contain memo/tapscript/custom blobs, which we
			// currently ignore while rebuilding OpenChannel shells.
			continue
		}
	}

	return nil
}

// auxSentinels mark keys that belong to other channel buckets. They are used
// as hard boundaries when trimming slack space from the aux payload.
var auxSentinels = [][]byte{
	[]byte("revocation-state-key"),
	[]byte("chan-commitment-key"),
	[]byte("commit-diff-key"),
}

// trimAuxData removes trailing zero padding from the aux region and cuts off
// the data once a known sibling key is encountered.
func trimAuxData(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	cutoff := len(data)
	for _, marker := range auxSentinels {
		if idx := bytes.Index(data, marker); idx >= 0 && idx < cutoff {
			cutoff = idx
		}
	}

	trimmed := bytes.TrimRight(data[:cutoff], "\x00")
	return trimmed
}

// populateAuxData reattaches revocation state, lease expiration, and other
// auxiliary fields that are stored outside the primary chan-info blob.
func (c *chanInfo) populateAuxData(r io.ReaderAt, keyOffset int64) error {
	state, err := findRevocationState(r, keyOffset)
	if err != nil {
		return err
	}
	c.remoteCurrent = state.remoteCurrent
	c.remoteNext = state.remoteNext
	c.revocationProd = state.producer
	c.revocationStore = state.store

	if c.chanType.HasLeaseExpiration() {
		if height, err := frozenHeight(r, keyOffset); err == nil {
			c.leaseExpiry = height
		}
	}

	return nil
}

func (c *chanInfo) buildChannel(commit *commitInfo) *channeldb.OpenChannel {
	chanID := c.shortID
	if chanID.BlockHeight == 0 {
		chanID.BlockHeight = c.fundingHeight
	}
	if c.chanType.HasZeroConf() {
		if c.hasConfirmed {
			chanID = c.confirmedScid
		} else {
			chanID.BlockHeight = c.fundingHeight
			chanID.TxIndex = 0
			chanID.TxPosition = 0
		}
	}

	channel := &channeldb.OpenChannel{
		ChanType:               c.chanType,
		ChainHash:              c.chainHash,
		FundingOutpoint:        c.outpoint,
		ShortChannelID:         chanID,
		IsPending:              c.isPending,
		IsInitiator:            c.isInitiator,
		FundingBroadcastHeight: c.fundingHeight,
		NumConfsRequired:       c.numConfs,
		ChannelFlags:           c.channelFlags,
		IdentityPub:            c.remoteIdentity,
		Capacity:               c.capacity,
		TotalMSatSent:          c.totalMsatSent,
		TotalMSatReceived:      c.totalMsatReceived,
		InitialLocalBalance:    c.initialLocalBalance,
		InitialRemoteBalance:   c.initialRemoteBalance,
		LocalChanCfg:           c.localCfg,
		RemoteChanCfg:          c.remoteCfg,
		RevocationKeyLocator:   c.revocationLocator,
		ThawHeight:             c.leaseExpiry,
	}
	setChannelStatus(channel, c.status)
	channel.RemoteCurrentRevocation = c.remoteCurrent
	channel.RemoteNextRevocation = c.remoteNext
	channel.RevocationProducer = c.revocationProd
	channel.RevocationStore = c.revocationStore

	if commit != nil && commit.Tx != nil {
		channel.LocalCommitment = channeldb.ChannelCommitment{
			CommitHeight:  commit.CommitHeight,
			LocalBalance:  lnwire.MilliSatoshi(commit.LocalBalance),
			RemoteBalance: lnwire.MilliSatoshi(commit.RemoteBalance),
			CommitFee:     btcutil.Amount(commit.CommitFee),
			CommitTx:      commit.Tx,
			CommitSig:     commit.CommitSig,
		}
	}

	return channel
}

// shouldReadFundingTx returns true when the serialized channel info is
// expected to contain the full funding transaction blob (single funder,
// initiator, and HasFundingTx flag set).
func shouldReadFundingTx(info *chanInfo) bool {
	if !info.chanType.IsSingleFunder() {
		return false
	}
	if !info.chanType.HasFundingTx() {
		return false
	}
	if !info.isInitiator {
		return false
	}
	return true
}

// frozenHeight looks up the frozen-chans sibling entry near the anchor offset
// to retrieve the stored thaw height for leased channels.
func frozenHeight(r io.ReaderAt, anchor int64) (uint32, error) {
	data, err := readSibling(r, anchor, "frozen-chans", 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

// readSibling scans a bounded window around the anchor and returns the value
// for another bucket key (for example frozen-chans) when present.
func readSibling(r io.ReaderAt, anchor int64, key string, size int) ([]byte, error) {
	start := anchor - siblingSearchRadius
	if start < 0 {
		start = 0
	}

	window := siblingSearchRadius*2 + int64(len(key)) + int64(size) + 16
	buf := make([]byte, window)
	n, err := r.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return nil, err
	}
	idx := bytes.Index(buf[:n], []byte(key))
	if idx == -1 {
		return nil, fmt.Errorf("%s not found near 0x%x", key, anchor)
	}

	valueStart := start + int64(idx) + int64(len(key))
	out := make([]byte, size)
	if _, err := r.ReadAt(out, valueStart); err != nil {
		return nil, err
	}
	return out, nil
}

// findCommitment searches within commitSearchRadius of the anchor for the
// local commitment blob and, if found, parses it into commitInfo.
// findCommitment searches for the local commitment serialization within
// commitSearchRadius of the provided anchor offset.
func findCommitment(r io.ReaderAt, anchor int64) (*commitInfo, error) {
	keyBytes := append([]byte(commitKey), byte(0x00))
	radius := int64(commitSearchRadius)
	start := anchor - radius
	if start < 0 {
		start = 0
	}

	bufLen := radius*2 + int64(len(keyBytes)) + 1
	buf := make([]byte, bufLen)
	n, err := r.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return nil, err
	}

	idx := bytes.Index(buf[:n], keyBytes)
	if idx == -1 {
		return nil, fmt.Errorf("commitment not found near 0x%x", anchor)
	}

	dataOffset := start + int64(idx) + int64(len(keyBytes))
	return parseCommitment(r, dataOffset)
}

// parseCommitment deserializes the commitment entry located at the supplied
// offset and returns the height, balances, tx, and signature information.
func parseCommitment(r io.ReaderAt, offset int64) (*commitInfo, error) {
	buf := make([]byte, commitmentReadLimit)
	n, err := r.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	reader := bytes.NewReader(buf[:n])
	info := &commitInfo{}

	if info.CommitHeight, err = readUint64(reader); err != nil {
		return nil, err
	}

	for i := 0; i < 4; i++ {
		if _, err := readUint64(reader); err != nil {
			return nil, err
		}
	}

	if info.LocalBalance, err = readUint64(reader); err != nil {
		return nil, err
	}
	if info.RemoteBalance, err = readUint64(reader); err != nil {
		return nil, err
	}
	if info.CommitFee, err = readUint64(reader); err != nil {
		return nil, err
	}

	if _, err := readUint64(reader); err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(0)
	if err := tx.Deserialize(reader); err != nil {
		return nil, err
	}
	info.Tx = tx

	sig, err := readVarBytes(reader, commitSigMaxSize)
	if err != nil {
		return nil, err
	}
	info.CommitSig = sig

	return info, nil
}

// revocationState mirrors the serialized revocation-state-key contents.
type revocationState struct {
	// remoteCurrent is the current revocation pubkey.
	remoteCurrent *btcec.PublicKey

	// remoteNext is the next revocation pubkey.
	remoteNext *btcec.PublicKey

	// producer is the remote shachain producer.
	producer shachain.Producer

	// store is the remote shachain store.
	store shachain.Store
}

// findRevocationState scans for the revocation-state-key entry near the
// provided anchor and parses its payload if present.
func findRevocationState(r io.ReaderAt, anchor int64) (*revocationState, error) {
	key := []byte("revocation-state-key")
	radius := int64(commitSearchRadius)
	start := anchor - radius
	if start < 0 {
		start = 0
	}

	bufLen := radius*2 + int64(len(key)) + 1
	buf := make([]byte, bufLen)
	n, err := r.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return nil, err
	}
	idx := bytes.Index(buf[:n], key)
	if idx == -1 {
		return nil, errRevocationNotFound
	}

	dataOffset := start + int64(idx) + int64(len(key))
	return parseRevocationState(r, dataOffset)
}

// parseRevocationState converts the revocation-state-key payload into the
// public keys, producer, and store structures needed for channel rescue.
func parseRevocationState(r io.ReaderAt, offset int64) (*revocationState, error) {
	buf := make([]byte, 1<<16)
	n, err := r.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	reader := bytes.NewReader(buf[:n])
	state := &revocationState{}
	if err := channeldb.ReadElements(reader,
		&state.remoteCurrent, &state.producer, &state.store,
	); err != nil {
		return nil, err
	}

	if reader.Len() > 0 {
		if err := channeldb.ReadElements(reader, &state.remoteNext); err != nil {
			return nil, err
		}
	}

	return state, nil
}

// readChannelConfig deserializes the channel config struct (dust limits,
// reserves, base points, etc.) from the provided reader.
func readChannelConfig(r io.Reader) (channeldb.ChannelConfig, error) {
	var cfg channeldb.ChannelConfig
	var err error

	if cfg.DustLimit, err = readAmt(r); err != nil {
		return cfg, err
	}
	if cfg.MaxPendingAmount, err = readMsat(r); err != nil {
		return cfg, err
	}
	if cfg.ChanReserve, err = readAmt(r); err != nil {
		return cfg, err
	}
	if cfg.MinHTLC, err = readMsat(r); err != nil {
		return cfg, err
	}
	if cfg.MaxAcceptedHtlcs, err = readUint16(r); err != nil {
		return cfg, err
	}
	if cfg.CsvDelay, err = readUint16(r); err != nil {
		return cfg, err
	}
	if cfg.MultiSigKey, err = readKeyDesc(r); err != nil {
		return cfg, err
	}
	if cfg.RevocationBasePoint, err = readKeyDesc(r); err != nil {
		return cfg, err
	}
	if cfg.PaymentBasePoint, err = readKeyDesc(r); err != nil {
		return cfg, err
	}
	if cfg.DelayBasePoint, err = readKeyDesc(r); err != nil {
		return cfg, err
	}
	if cfg.HtlcBasePoint, err = readKeyDesc(r); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// readKeyDesc reads a KeyDescriptor, including the optional public key, from
// the serialized channel config stream.
func readKeyDesc(r io.Reader) (keychain.KeyDescriptor, error) {
	var desc keychain.KeyDescriptor
	fam, err := readUint32(r)
	if err != nil {
		return desc, err
	}
	desc.KeyLocator.Family = keychain.KeyFamily(fam)

	idx, err := readUint32(r)
	if err != nil {
		return desc, err
	}
	desc.KeyLocator.Index = idx

	hasPub, err := readBool(r)
	if err != nil {
		return desc, err
	}
	if hasPub {
		var buf [33]byte
		if err := readInto(r, buf[:]); err != nil {
			return desc, err
		}
		desc.PubKey, err = btcec.ParsePubKey(buf[:])
		if err != nil {
			return desc, err
		}
	}

	return desc, nil
}

// readInto copies exactly len(dst) bytes from the reader into dst.
func readInto(r io.Reader, dst []byte) error {
	_, err := io.ReadFull(r, dst)
	return err
}

// readBool reads a single byte and interprets it as a boolean value.
func readBool(r io.Reader) (bool, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return false, err
	}
	switch b[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("invalid bool byte %d", b[0])
	}
}

// readUint16 reads a big-endian uint16 from the reader.
func readUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// readUint32 reads a big-endian uint32 from the reader.
func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// readUint64 reads a big-endian uint64 from the reader.
func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// readVarInt parses the compact uint encoding used throughout the channel
// serialization.
func readVarInt(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return 0, err
	}
	switch buf[0] {
	case 0xfd:
		if _, err := io.ReadFull(r, buf[:2]); err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(buf[:2])), nil
	case 0xfe:
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(buf[:4])), nil
	case 0xff:
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(buf[:]), nil
	default:
		return uint64(buf[0]), nil
	}
}

// readVarBytes reads a varint length prefix followed by the payload, enforcing
// a caller supplied maximum size.
func readVarBytes(r io.Reader, max uint32) ([]byte, error) {
	length, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if length > uint64(max) {
		return nil, fmt.Errorf("var bytes too large: %d", length)
	}
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readAmt reads a satoshi-denominated amount.
func readAmt(r io.Reader) (btcutil.Amount, error) {
	val, err := readUint64(r)
	if err != nil {
		return 0, err
	}
	return btcutil.Amount(val), nil
}

// readMsat reads a milli-satoshi amount.
func readMsat(r io.Reader) (lnwire.MilliSatoshi, error) {
	val, err := readUint64(r)
	if err != nil {
		return 0, err
	}
	return lnwire.MilliSatoshi(val), nil
}
