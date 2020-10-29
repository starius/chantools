package main

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/lightningnetwork/lnd/keychain"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/guggero/chantools/lnd"
)

type signRescueFundingCommand struct {
	RootKey string `long:"rootkey" description:"BIP32 HD root (m/) key to derive the key for our part of the signature from."`
	Psbt    string `long:"psbt" description:"The Partially Signed Bitcoin Transaction that was provided by the initiator of the channel to rescue."`
}

func (c *signRescueFundingCommand) Execute(_ []string) error {
	setupChainParams(cfg)

	var (
		extendedKey *hdkeychain.ExtendedKey
		err         error
	)

	// Check that root key is valid or fall back to console input.
	switch {
	case c.RootKey != "":
		extendedKey, err = hdkeychain.NewKeyFromString(c.RootKey)

	default:
		extendedKey, _, err = lnd.ReadAezeed(chainParams)
	}
	if err != nil {
		return fmt.Errorf("error reading root key: %v", err)
	}

	signer := &lnd.Signer{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}

	// Decode the PSBT.
	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader([]byte(c.Psbt)), true,
	)
	if err != nil {
		return fmt.Errorf("error decoding PSBT: %v", err)
	}

	return signRescueFunding(extendedKey, packet, signer)
}

func signRescueFunding(rootKey *hdkeychain.ExtendedKey,
	packet *psbt.Packet, signer *lnd.Signer) error {

	// First, we need to derive the correct branch from the local root key.
	localMultisig, err := lnd.DeriveChildren(rootKey, []uint32{
		lnd.HardenedKeyStart + uint32(keychain.BIP0043Purpose),
		lnd.HardenedKeyStart + chainParams.HDCoinType,
		lnd.HardenedKeyStart + uint32(keychain.KeyFamilyMultiSig),
		0,
	})
	if err != nil {
		return fmt.Errorf("could not derive local multisig key: %v",
			err)
	}

	// Now let's check that the packet has the expected proprietary key with
	// our pubkey that we need to sign with.
	if len(packet.Inputs) != 1 {
		return fmt.Errorf("invalid PSBT, expected 1 input, got %d",
			len(packet.Inputs))
	}
	if len(packet.Inputs[0].Unknowns) != 1 {
		return fmt.Errorf("invalid PSBT, expected 1 unknown in input, "+
			"got %d", len(packet.Inputs[0].Unknowns))
	}
	unknown := packet.Inputs[0].Unknowns[0]
	if !bytes.Equal(unknown.Key, PsbtKeyTypeOutputMissingSigPubkey) {
		return fmt.Errorf("invalid PSBT, unknown has invalid key %x, "+
			"expected %x", unknown.Key,
			PsbtKeyTypeOutputMissingSigPubkey)
	}
	targetKey, err := btcec.ParsePubKey(unknown.Value, btcec.S256())
	if err != nil {
		return fmt.Errorf("invalid PSBT, proprietary key has invalid "+
			"pubkey: %v", err)
	}

	// Now we can look up the local key and check the PSBT further, then
	// add our signature.
	localKeyDesc, err := findLocalMultisigKey(localMultisig, targetKey)
	if err != nil {
		return fmt.Errorf("could not find local multisig key: %v", err)
	}
	if len(packet.Inputs[0].WitnessScript) == 0 {
		return fmt.Errorf("invalid PSBT, missing witness script")
	}
	witnessScript := packet.Inputs[0].WitnessScript
	if packet.Inputs[0].WitnessUtxo == nil {
		return fmt.Errorf("invalid PSBT, witness UTXO missing")
	}
	utxo := packet.Inputs[0].WitnessUtxo

	err = signer.AddPartialSignature(
		packet, *localKeyDesc, utxo, witnessScript, 0,
	)
	if err != nil {
		return fmt.Errorf("error adding partial signature: %v", err)
	}

	// We're almost done. Now we just need to make sure we can finalize and
	// extract the final TX.
	err = psbt.MaybeFinalizeAll(packet)
	if err != nil {
		return fmt.Errorf("error finalizing PSBT: %v", err)
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		return fmt.Errorf("unable to extract final TX: %v", err)
	}
	var buf bytes.Buffer
	err = finalTx.Serialize(&buf)
	if err != nil {
		return fmt.Errorf("unable to serialize final TX: %v", err)
	}

	fmt.Printf("Success, we counter signed the PSBT and extracted the "+
		"final\ntransaction. Please publish this using any bitcoin "+
		"node:\n\n%x\n\n", buf.Bytes())

	return nil
}

func findLocalMultisigKey(multisigBranch *hdkeychain.ExtendedKey,
	targetPubkey *btcec.PublicKey) (*keychain.KeyDescriptor, error) {

	// Loop through the local multisig keys to find the target key.
	for index := uint32(0); index < MaxChannelLookup; index++ {
		currentKey, err := multisigBranch.Child(index)
		if err != nil {
			return nil, fmt.Errorf("error deriving child key: %v",
				err)
		}

		currentPubkey, err := currentKey.ECPubKey()
		if err != nil {
			return nil, fmt.Errorf("error deriving public key: %v",
				err)
		}

		if !targetPubkey.IsEqual(currentPubkey) {
			continue
		}

		return &keychain.KeyDescriptor{
			PubKey: currentPubkey,
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyMultiSig,
				Index:  index,
			},
		}, nil
	}

	return nil, fmt.Errorf("no matching pubkeys found")
}