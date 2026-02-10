/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/httpupgrade"
	"github.com/daeuniverse/outbound/transport/tls"
	"github.com/daeuniverse/outbound/transport/ws"
)

func init() {
	dialer.FromLinkRegister("vless", NewVless)
}

type Vless struct {
	Name          string
	Server        string
	Port          int
	ID            string
	Flow          string
	Net           string
	Type          string
	Host          string
	SNI           string
	Path          string
	TLS           string
	Alpn          string
	AllowInsecure bool
	Fingerprint   string
	PublicKey     string
	ShortId       string
	SpiderX       string
	ServiceName   string
}

func NewVless(link string) (dialer.Dialer, *dialer.Property, error) {
	s, err := ParseVlessURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: "vless",
		Link:     s.ExportToURL(),
	}, nil
}

func (s *Vless) Dialer(option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error) {
	var err error
	d := parentDialer

	// Apply TLS/Reality transport
	switch s.TLS {
	case "tls":
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		if sni == "" {
			sni = s.Server
		}
		tlsConfig := tls.TLSConfig{
			Host:          net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			Sni:           sni,
			Alpn:          s.Alpn,
			AllowInsecure: s.AllowInsecure || option.AllowInsecure,
		}
		if d, err = tlsConfig.Dialer(option, d); err != nil {
			return nil, err
		}
	case "reality":
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		if sni == "" {
			sni = s.Server
		}
		tlsConfig := tls.TLSConfig{
			Host:          net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			Sni:           sni,
			AllowInsecure: s.AllowInsecure || option.AllowInsecure,
		}
		if d, err = tlsConfig.Dialer(option, d); err != nil {
			return nil, err
		}
	}

	// Apply network transport
	switch strings.ToLower(s.Net) {
	case "ws":
		host := s.Host
		if host == "" {
			host = s.Server
		}
		wsConfig := &ws.WsConfig{
			Scheme:        "ws",
			Host:          net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			Path:          s.Path,
			Hostname:      host,
			Sni:           s.SNI,
			AllowInsecure: s.AllowInsecure || option.AllowInsecure,
		}
		if d, err = wsConfig.Dialer(option, d); err != nil {
			return nil, err
		}
	case "grpc":
		serviceName := s.ServiceName
		if serviceName == "" {
			serviceName = s.Path
		}
		if serviceName == "" {
			serviceName = "GunService"
		}
		sni := s.SNI
		if sni == "" {
			sni = s.Server
		}
		d = &grpc.Dialer{
			StatelessDialer: protocol.StatelessDialer{
				ParentDialer: d,
			},
			ServiceName:   serviceName,
			ServerName:    sni,
			AllowInsecure: s.AllowInsecure || option.AllowInsecure,
		}
	case "httpupgrade":
		u := url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			RawQuery: url.Values{
				"host": []string{s.Host},
				"path": []string{s.Path},
			}.Encode(),
		}
		if d, err = httpupgrade.NewDialer(u.String(), d); err != nil {
			return nil, err
		}
	case "tcp", "":
		// No additional transport needed
	default:
		return nil, fmt.Errorf("unsupported network transport: %v", s.Net)
	}

	// Apply VLESS protocol
	return protocol.NewDialer("vless", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Password:     s.ID,
		Feature1:     s.Flow,
	})
}

func ParseVlessURL(vless string) (data *Vless, err error) {
	u, err := url.Parse(vless)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", u.Port())
	}
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	data = &Vless{
		Name:          u.Fragment,
		Server:        u.Hostname(),
		Port:          port,
		ID:            u.User.String(),
		Net:           u.Query().Get("type"),
		Type:          u.Query().Get("headerType"),
		Host:          u.Query().Get("host"),
		SNI:           u.Query().Get("sni"),
		Path:          u.Query().Get("path"),
		TLS:           u.Query().Get("security"),
		Flow:          u.Query().Get("flow"),
		Alpn:          u.Query().Get("alpn"),
		AllowInsecure: allowInsecure,
		Fingerprint:   u.Query().Get("fp"),
		PublicKey:     u.Query().Get("pbk"),
		ShortId:       u.Query().Get("sid"),
		SpiderX:       u.Query().Get("spx"),
		ServiceName:   u.Query().Get("serviceName"),
	}
	if data.Net == "" {
		data.Net = "tcp"
	}
	if data.Net == "grpc" && data.ServiceName == "" {
		data.ServiceName = u.Query().Get("serviceName")
	}
	if data.Type == "" {
		data.Type = "none"
	}
	if data.TLS == "" {
		data.TLS = "none"
	}
	return data, nil
}

func (s *Vless) ExportToURL() string {
	var query = make(url.Values)
	common.SetValue(&query, "type", s.Net)
	common.SetValue(&query, "security", s.TLS)
	switch s.Net {
	case "websocket", "ws", "http", "h2", "httpupgrade":
		common.SetValue(&query, "path", s.Path)
		common.SetValue(&query, "host", s.Host)
	case "tcp":
		common.SetValue(&query, "headerType", s.Type)
		common.SetValue(&query, "host", s.Host)
		common.SetValue(&query, "path", s.Path)
	case "grpc":
		common.SetValue(&query, "serviceName", s.ServiceName)
	}

	if s.TLS != "none" {
		common.SetValue(&query, "sni", s.SNI)
		common.SetValue(&query, "alpn", s.Alpn)
		common.SetValue(&query, "flow", s.Flow)
		common.SetValue(&query, "fp", s.Fingerprint)
	}

	if s.TLS == "reality" {
		common.SetValue(&query, "pbk", s.PublicKey)
		common.SetValue(&query, "sid", s.ShortId)
		common.SetValue(&query, "spx", s.SpiderX)
	}

	U := url.URL{
		Scheme:   "vless",
		User:     url.User(s.ID),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		RawQuery: query.Encode(),
		Fragment: s.Name,
	}
	return U.String()
}
