package main

import (
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/chantools/dump"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightninglabs/chantools/rescue"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/spf13/cobra"
)

type dumpChannelsCommand struct {
	ChannelDB    string
	Closed       bool
	Pending      bool
	WaitingClose bool
	Recover      bool

	cmd *cobra.Command
}

func newDumpChannelsCommand() *cobra.Command {
	cc := &dumpChannelsCommand{}
	cc.cmd = &cobra.Command{
		Use: "dumpchannels",
		Short: "Dump all channel information from an lnd channel " +
			"database",
		Long: `This command dumps all open and pending channels from the
given lnd channel.db gile in a human readable format.`,
		Example: `chantools dumpchannels \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to dump "+
			"channels from",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Closed, "closed", false, "dump closed channels instead of "+
			"open",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Pending, "pending", false, "dump pending channels instead "+
			"of open",
	)
	cc.cmd.Flags().BoolVar(
		&cc.WaitingClose, "waiting_close", false, "dump waiting close "+
			"channels instead of open",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Recover, "recover", false, "fall back to raw channel.db "+
			"recovery when dumping open channels and the DB cannot be "+
			"opened normally",
	)

	return cc.cmd
}

func (c *dumpChannelsCommand) Execute(_ *cobra.Command, _ []string) error {
	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return errors.New("channel DB is required")
	}
	if (c.Closed && c.Pending) || (c.Closed && c.WaitingClose) ||
		(c.Pending && c.WaitingClose) {

		return errors.New("can only specify one flag at a time")
	}

	if c.Closed || c.Pending || c.WaitingClose {
		if c.Recover {
			return errors.New("--recover can only be used when " +
				"dumping open channels")
		}

		db, _, err := lnd.OpenDB(c.ChannelDB, true)
		if err != nil {
			return fmt.Errorf("error opening channel DB: %w", err)
		}
		defer func() { _ = db.Close() }()

		switch {
		case c.Closed:
			return dumpClosedChannelInfo(db.ChannelStateDB())
		case c.Pending:
			return dumpPendingChannelInfo(db.ChannelStateDB())
		case c.WaitingClose:
			return dumpWaitingCloseChannelInfo(db.ChannelStateDB())
		}
	}

	channels, err := rescue.LoadChannels(c.ChannelDB, c.Recover)
	if err != nil {
		return err
	}

	return dumpOpenChannelInfo(channels)
}

func dumpOpenChannelInfo(channels []*channeldb.OpenChannel) error {
	dumpChannels, err := dump.OpenChannelDump(channels, chainParams)
	if err != nil {
		return fmt.Errorf("error converting to dump format: %w", err)
	}

	spew.Dump(dumpChannels)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(spew.Sdump(dumpChannels))

	return nil
}

func dumpClosedChannelInfo(chanDb *channeldb.ChannelStateDB) error {
	channels, err := chanDb.FetchClosedChannels(false)
	if err != nil {
		return err
	}

	historicalChannels := make([]*channeldb.OpenChannel, len(channels))
	for idx := range channels {
		closedChan := channels[idx]
		histChan, err := chanDb.FetchHistoricalChannel(
			&closedChan.ChanPoint,
		)

		switch {
		// The channel was closed in a pre-historic version of lnd.
		// Ignore the error.
		case errors.Is(err, channeldb.ErrNoHistoricalBucket):
		case errors.Is(err, channeldb.ErrChannelNotFound):

		case err == nil:
			historicalChannels[idx] = histChan

		// Non-nil error not due to older versions of lnd.
		default:
			return err
		}
	}

	dumpChannels, err := dump.ClosedChannelDump(
		channels, historicalChannels, chainParams,
	)
	if err != nil {
		return fmt.Errorf("error converting to dump format: %w", err)
	}

	spew.Dump(dumpChannels)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(spew.Sdump(dumpChannels))

	return nil
}

func dumpPendingChannelInfo(chanDb *channeldb.ChannelStateDB) error {
	channels, err := chanDb.FetchPendingChannels()
	if err != nil {
		return err
	}

	dumpChannels, err := dump.OpenChannelDump(channels, chainParams)
	if err != nil {
		return fmt.Errorf("error converting to dump format: %w", err)
	}

	spew.Dump(dumpChannels)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(spew.Sdump(dumpChannels))

	return nil
}

func dumpWaitingCloseChannelInfo(chanDb *channeldb.ChannelStateDB) error {
	channels, err := chanDb.FetchWaitingCloseChannels()
	if err != nil {
		return err
	}

	dumpChannels, err := dump.OpenChannelDump(channels, chainParams)
	if err != nil {
		return fmt.Errorf("error converting to dump format: %w", err)
	}

	spew.Dump(dumpChannels)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(spew.Sdump(dumpChannels))

	return nil
}
