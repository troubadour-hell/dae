/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/oops"
	"golang.org/x/sys/unix"
)

const (
	// Value from OpenWRT default sysctl config
	DefaultNatTimeoutTCPEstablished = 21600 * time.Second
)

func (c *ControlPlane) handleConn(lConn net.Conn) error {
	// Sniff target domain.
	sniffer := sniffing.NewConnSniffer(lConn, c.sniffingTimeout)
	// ConnSniffer should be used later, so we cannot close it now.
	defer sniffer.Close()

	domain, err := sniffer.SniffTcp()
	if err != nil && !sniffing.IsSniffingError(err) {
		// We ignore lConn errors or temporary network errors
		if _, ok := IsNetError(err); ok {
			return nil
		}
		// Avoid massive EOF logs. A common case: clients (e.g. browser) tend to establish both
		// ipv4 and ipv6 connections, and then close one of them.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return oops.Wrapf(err, "Sniff Failed")
	}

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return oops.Wrapf(err, "failed to retrieve target info %v", dst.String())
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	// Route
	networkType := &common.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	dialOption, err := c.RouteDialOption(&RouteParam{
		routingResult: routingResult,
		networkType:   networkType,
		Domain:        domain,
		Src:           src,
		Dest:          dst,
	})
	if err != nil {
		return err
	}

	labels := prometheus.Labels{
		"outbound": dialOption.Outbound.Name,
		"subtag":   dialOption.Dialer.Property.SubscriptionTag,
		"dialer":   dialOption.Dialer.Name,
		"network":  networkType.String(),
	}

	// Dial
	LogDial(src, dst, domain, dialOption, networkType, routingResult)
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	start := time.Now()
	rConn, err := dialOption.Dialer.DialContext(ctx, "tcp", dialOption.DialTarget)
	if err != nil {
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		netErr, ok := IsNetError(err)
		err = oops.
			In("DialContext").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to DialContext")
		if !ok {
			return err
		} else if !netErr.Timeout() {
			if dialOption.Dialer.NeedAliveState() {
				common.ErrorCount.With(labels).Inc()
				dialOption.Dialer.ReportUnavailable()
				return err
			}
		}
		return nil
	}

	elapsed := time.Since(start).Seconds()
	common.DialLatency.With(labels).Observe(elapsed)
	activeConnectionsCounter := common.ActiveConnections.With(labels)
	activeConnectionsCounter.Inc()
	defer activeConnectionsCounter.Dec()

	counterForTraffic := common.TrafficBytes.With(prometheus.Labels{
		"outbound": dialOption.Outbound.Name,
		"subtag":   dialOption.Dialer.Property.SubscriptionTag,
		"network":  networkType.String(),
		"dst":      dialOption.DialTarget,
	})
	rLogConn := NewTrafficLogConn(rConn, c.trafficLogger, counterForTraffic, src.Addr().String(), dialOption.DialTarget)
	defer rLogConn.Close()

	// Relay
	if err := RelayTCP(sniffer, rLogConn); err != nil {
		netErr, ok := IsNetError(err)
		err = oops.
			In("RelayTCP").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to RelayTCP")
		if !ok {
			return err
		} else if !netErr.Timeout() && dialOption.Dialer.NeedAliveState() {
			common.ErrorCount.With(labels).Inc()
			dialOption.Dialer.ReportUnavailable()
			return err
		}
	}
	// case strings.HasSuffix(err.Error(), "write: broken pipe"),
	// 	strings.HasSuffix(err.Error(), "i/o timeout"),
	// 	strings.HasPrefix(err.Error(), "EOF"),
	// 	strings.HasSuffix(err.Error(), "connection reset by peer"),
	// 	strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
	// 	strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
	return nil
}

type relayResult struct {
	err       error
	direction bool // true for lConn->rConn, false for rConn->lConn
}

func relayDirection(dst, src net.Conn, result chan<- relayResult, direction bool) {
	src.SetReadDeadline(time.Now().Add(DefaultNatTimeoutTCPEstablished))

	// As `io.Copy` uses a 32KB buffer, we create a buffer of the same size.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	bufSize := 16 * 1024
	if direction {
		bufSize = 8 * 1024
	}
	bufPtr := pool.GetBuffer(bufSize)
	defer pool.PutBuffer(bufPtr)
	_, err := io.CopyBuffer(dst, src, bufPtr)
	result <- relayResult{err: err, direction: direction}
	if err != nil {
		dst.Close()
	} else if writeCloser, ok := dst.(netproxy.CloseWriter); ok {
		writeCloser.CloseWrite()
	} else {
		dst.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn net.Conn) error {
	resultCh := make(chan relayResult, 2)

	// Start relay goroutines for both directions.
	go relayDirection(lConn, rConn, resultCh, false) // rConn -> lConn
	go relayDirection(rConn, lConn, resultCh, true)  // lConn -> rConn
	result := <-resultCh
	<-resultCh

	err := result.err
	if err != nil {
		// We ignore lConn errors or temporary network errors
		// TODO: Why get EOF as an error?
		if result.direction { // l -> r
			switch {
			case err == io.EOF,
				strings.HasSuffix(err.Error(), "canceled by remote with error code 0"), // rConn closed
				strings.Contains(err.Error(), "read:"):                                 // lConn Read
				err = nil
			default:
				err = oops.In("lConn -> rConn Relay").Wrap(err)
			}

		} else { // r -> l
			switch {
			case strings.Contains(err.Error(), "write:"): // lConn Write
				err = nil
			default:
				err = oops.In("rConn -> lConn Relay").Wrap(err)
			}
		}
	}

	return err
}
