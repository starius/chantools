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
	errChannelNotFound    = errors.New("no channels recovered")
	errRevocationNotFound = errors.New("revocation state not found")
)

const (
	infoKey             = "chan-info-key"
	commitKey           = "chan-commitment-key"
	chunkSize           = 4 << 20
	commitSearchRadius  = 1 << 15
	siblingSearchRadius = 4 << 10
	headerReadLimit     = 1 << 20
	commitmentReadLimit = 1 << 20
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
// The reader must implement io.ReaderAt so random access near recovered keys
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
// path. If the Bolt database can be opened, it simply returns the channels
// fetched through channeldb. If the DB cannot be opened and rescue mode is
// enabled, the function falls back to scanning the raw file and rebuilding the
// channels from disk. When rescue is false, the original open error is
// returned.
func LoadChannels(dbPath string, rescue bool) ([]*channeldb.OpenChannel, error) {
	channelDB, _, err := lnd.OpenDB(dbPath, true)
	if err == nil {
		defer func() { _ = channelDB.Close() }()

		return channelDB.ChannelStateDB().FetchAllChannels()
	}
	if !rescue {
		return nil, fmt.Errorf("error opening channel DB: %w", err)
	}

	file, fileErr := os.Open(dbPath)
	if fileErr != nil {
		return nil, fmt.Errorf("error opening channel DB for rescue: %w",
			fileErr)
	}
	defer func() { _ = file.Close() }()

	recovered, recErr := RescueChannels(file)
	if recErr != nil {
		return nil, recErr
	}

	return recovered, nil
}

// setChannelStatus mutates the private chanStatus field on channeldb.OpenChannel
// using reflection+unsafe so recovered channels retain their waiting-close
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

func scanForChannels(r io.ReaderAt) ([]*channeldb.OpenChannel, error) {
	key := []byte(infoKey)
	buf := make([]byte, chunkSize+len(key)-1)
	tail := make([]byte, len(key)-1)
	tailLen := 0
	var channels []*channeldb.OpenChannel
	var offset int64

	for {
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
				channel, err := recoverAtOffset(r, absolute)
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

func recoverAtOffset(r io.ReaderAt, keyOffset int64) (*channeldb.OpenChannel, error) {
	dataOffset := keyOffset + int64(len(infoKey))
	info, err := parseChanInfo(r, keyOffset, dataOffset)
	if err != nil {
		return nil, err
	}

	commit, err := findCommitment(r, keyOffset)
	if err != nil {
		return nil, err
	}

	if err := info.populateAuxData(r, keyOffset); err != nil {
		return nil, err
	}

	return info.buildChannel(commit), nil
}

type chanInfo struct {
	keyOffset  int64
	dataOffset int64

	chanType  channeldb.ChannelType
	chainHash chainhash.Hash
	outpoint  wire.OutPoint
	shortID   lnwire.ShortChannelID

	isPending   bool
	isInitiator bool
	status      channeldb.ChannelStatus

	fundingHeight  uint32
	numConfs       uint16
	channelFlags   lnwire.FundingFlag
	remoteIdentity *btcec.PublicKey

	capacity          btcutil.Amount
	totalMsatSent     lnwire.MilliSatoshi
	totalMsatReceived lnwire.MilliSatoshi

	localCfg  channeldb.ChannelConfig
	remoteCfg channeldb.ChannelConfig

	revocationLocator    keychain.KeyLocator
	confirmedScid        lnwire.ShortChannelID
	hasConfirmed         bool
	confirmationHeight   uint32
	initialLocalBalance  lnwire.MilliSatoshi
	initialRemoteBalance lnwire.MilliSatoshi
	leaseExpiry          uint32
	remoteCurrent        *btcec.PublicKey
	remoteNext           *btcec.PublicKey
	revocationProd       shachain.Producer
	revocationStore      shachain.Store
}

type commitInfo struct {
	CommitHeight  uint64
	LocalBalance  uint64
	RemoteBalance uint64
	CommitFee     uint64
	Tx            *wire.MsgTx
	CommitSig     []byte
}

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
		if t == 0 || t > maxAuxType {
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
		case 1:
			if len(field) != 8 {
				return fmt.Errorf("unexpected key locator length %d", len(field))
			}
			c.revocationLocator.Family = keychain.KeyFamily(binary.BigEndian.Uint32(field[:4]))
			c.revocationLocator.Index = binary.BigEndian.Uint32(field[4:])

		case 2:
			if len(field) != 8 {
				return fmt.Errorf("unexpected local balance length %d", len(field))
			}
			c.initialLocalBalance = lnwire.MilliSatoshi(binary.BigEndian.Uint64(field))

		case 3:
			if len(field) != 8 {
				return fmt.Errorf("unexpected remote balance length %d", len(field))
			}
			c.initialRemoteBalance = lnwire.MilliSatoshi(binary.BigEndian.Uint64(field))

		case 4:
			if len(field) != 8 {
				return fmt.Errorf("unexpected real scid size %d", len(field))
			}
			val := binary.BigEndian.Uint64(field)
			c.confirmedScid = lnwire.NewShortChanIDFromInt(val)
			if c.confirmedScid.BlockHeight != 0 {
				c.hasConfirmed = true
			}

		case 8:
			if len(field) != 4 {
				return fmt.Errorf("unexpected confirmation height len %d", len(field))
			}
			c.confirmationHeight = binary.BigEndian.Uint32(field)

		default:
			// Types 5-7 contain memo/tapscript/custom blobs, which we
			// do not currently surface.
			continue
		}
	}

	return nil
}

var auxSentinels = [][]byte{
	[]byte("revocation-state-key"),
	[]byte("chan-commitment-key"),
	[]byte("commit-diff-key"),
}

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

func frozenHeight(r io.ReaderAt, anchor int64) (uint32, error) {
	data, err := readSibling(r, anchor, "frozen-chans", 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

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

	sig, err := readVarBytes(reader, 66000)
	if err != nil {
		return nil, err
	}
	info.CommitSig = sig

	return info, nil
}

type revocationState struct {
	remoteCurrent *btcec.PublicKey
	remoteNext    *btcec.PublicKey
	producer      shachain.Producer
	store         shachain.Store
}

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

func readInto(r io.Reader, dst []byte) error {
	_, err := io.ReadFull(r, dst)
	return err
}

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

func readUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

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

func readAmt(r io.Reader) (btcutil.Amount, error) {
	val, err := readUint64(r)
	if err != nil {
		return 0, err
	}
	return btcutil.Amount(val), nil
}

func readMsat(r io.Reader) (lnwire.MilliSatoshi, error) {
	val, err := readUint64(r)
	if err != nil {
		return 0, err
	}
	return lnwire.MilliSatoshi(val), nil
}
