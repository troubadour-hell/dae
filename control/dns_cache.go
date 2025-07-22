/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type AnswerAndDeadline struct {
	Answer           []dnsmessage.RR
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
}

type DnsCache struct {
	DomainBitmap []uint32
	AnswerPerMac map[[6]uint8]AnswerAndDeadline
}

func (c *DnsCache) FillInto(mac [6]uint8, req *dnsmessage.Msg) bool {
	answerAndDeadline, ok := c.AnswerPerMac[mac]
	if !ok {
		// Tries fake mac.
		answerAndDeadline, ok = c.AnswerPerMac[[6]uint8{}]
	}
	if ok {
		req.Response = true
		req.RecursionAvailable = true
		req.Truncated = false
		req.Answer = deepcopy.Copy(answerAndDeadline.Answer).([]dnsmessage.RR)
		req.Rcode = dnsmessage.RcodeSuccess
	}
	return ok
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, answerAndDeadLine := range c.AnswerPerMac {
		for _, ans := range answerAndDeadLine.Answer {
			switch body := ans.(type) {
			case *dnsmessage.A:
				if !ip.Is4() {
					continue
				}
				if a, ok := netip.AddrFromSlice(body.A); ok && a == ip {
					return true
				}
			case *dnsmessage.AAAA:
				if !ip.Is6() {
					continue
				}
				if a, ok := netip.AddrFromSlice(body.AAAA); ok && a == ip {
					return true
				}
			}
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	for _, answerAndDeadLine := range c.AnswerPerMac {
		for _, ans := range answerAndDeadLine.Answer {
			switch ans.(type) {
			case *dnsmessage.A, *dnsmessage.AAAA:
				return true
			}
		}
	}
	return false
}
