package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func main() {
	err := attachXDP()
	if err != nil {
		logrus.Error(err)
	}
}

func attachXDP() error {
	logrus.Info("Starting nfNat...")
	spec, err := ebpf.LoadCollectionSpec(config.XdpProg)
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	dp := coll.Programs["process_rx"]
	if dp == nil {
		return fmt.Errorf("eBPF prog 'process_rx' not found")
	}

	link, err := netlink.LinkByName(config.Iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFd(link, dp.FD()); err != nil {
		return err
	}

	defer (func() {
		if err := netlink.LinkSetXdpFd(link, -1); err != nil {
			fmt.Println(err.Error())
		}
	})()

	logrus.Infof("Running nfNat on %s", config.Iface)

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Stopping nfNat...")
	return nil
}
