/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

type DnsCache struct {
	Answers   []dnsmessage.RR
	FetchedAt time.Time
	timer     *time.Timer
}

// Parse ips from DNS resp answers.
func GetIp(rr dnsmessage.RR) (netip.Addr, bool) {
	var (
		ip netip.Addr
		ok bool
	)
	switch body := rr.(type) {
	case *dnsmessage.A:
		ip, ok = netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		ip, ok = netip.AddrFromSlice(body.AAAA)
	}
	if !ok || ip.IsUnspecified() {
		return ip, false
	}
	return ip, true
}

func FillInto(msg *dnsmessage.Msg, cache *DnsCache) bool {
	// Ugly copying RR logic to avoid concurrent read/write TTL.
	// TODO: Optimize this by byte-level copying?
	m := &dnsmessage.Msg{}
	ttls := make([]uint32, 0)
	ttlDeduction := uint32(time.Since(cache.FetchedAt).Seconds())
	for _, ans := range cache.Answers {
		if ans.Header().Ttl > ttlDeduction {
			ttls = append(ttls, ans.Header().Ttl-ttlDeduction)
			m.Answer = append(m.Answer, ans)
		}
	}
	if len(m.Answer) == 0 {
		return false
	}
	m = m.Copy()
	for i := range m.Answer {
		m.Answer[i].Header().Ttl = ttls[i]
	}
	msg.Answer = m.Answer
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
	return true
}

func IncludeAnyIpInMsg(msg *dnsmessage.Msg) bool {
	for _, ans := range msg.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

type commonDnsCache[K comparable] struct {
	cache sync.Map
}

func newCommonDnsCache[K comparable]() *commonDnsCache[K] {
	return &commonDnsCache[K]{}
}

func (c *commonDnsCache[K]) Get(cacheKey K) *DnsCache {
	val, ok := c.cache.Load(cacheKey)
	if !ok {
		return nil
	}
	return val.(*DnsCache)
}

func (c *commonDnsCache[K]) UpdateAnswers(key K, answers []dnsmessage.RR, fixedTtl int) *DnsCache {
	if len(answers) == 0 {
		return nil
	}

	var minTTL uint32 = math.MaxUint32
	if fixedTtl > 0 {
		minTTL = uint32(fixedTtl)
		for _, ans := range answers {
			ans.Header().Ttl = uint32(fixedTtl)
		}
	} else {
		for _, ans := range answers {
			if ttl := ans.Header().Ttl; ttl < minTTL {
				minTTL = ttl
			}
		}
	}
	if minTTL == 0 || minTTL == math.MaxUint32 {
		return nil
	}
	newCache := &DnsCache{
		Answers:   answers,
		FetchedAt: time.Now(),
	}
	newCache.timer = time.AfterFunc(time.Duration(minTTL)*time.Second, func() {
		actual, loaded := c.cache.Load(key)
		if loaded && actual == newCache {
			if c.cache.CompareAndDelete(key, newCache) {
				common.DnsCacheSize.Dec()
			}
		}
	})

	oldVal, loaded := c.cache.Swap(key, newCache)
	if loaded {
		oldVal.(*DnsCache).timer.Stop()
	} else {
		common.DnsCacheSize.Inc()
	}

	return newCache
}
