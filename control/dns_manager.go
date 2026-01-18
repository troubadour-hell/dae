package control

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

const (
	dnsRetryInterval = 1 * time.Second
	dnsRetryCount    = 2
)

type DnsManager struct {
	conn    net.Conn
	recvMap sync.Map // map[uint32]chan *dnsmessage.Msg
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
}

func NewDnsManager(conn net.Conn, stream bool) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		stream: stream,
	}
	go m.run()
	return m
}

func (m *DnsManager) run() {
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		var data []byte
		var ok bool
		if data, ok = m.read(buf); !ok {
			m.Close()
			return
		}
		m.feed(data)
	}
}

func (m *DnsManager) read(buf []byte) (data []byte, ok bool) {
	var err error
	if m.stream {
		msgLenBuf := buf[:2]
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, msgLenBuf); err != nil {
			log.WithError(err).Infof("failed to read tcp DNS resp payload length")
			return
		}
		msgLen := int(binary.BigEndian.Uint16(msgLenBuf))
		if msgLen > len(buf) {
			log.WithError(err).Errorf("tcp dns msg len too large: %d > %d", msgLen, len(buf))
			return
		}
		data = buf[:msgLen]
		if _, err = io.ReadFull(m.conn, data); err != nil {
			log.WithError(err).Infof("failed to read tcp DNS resp payload")
			return
		}
	} else {
		var n int
		if n, err = m.conn.Read(buf); err != nil {
			log.WithError(err).Errorf("failed to read udp DNS resp payload")
			return
		}
		data = buf[:n]
	}
	return data, true
}

func (m *DnsManager) feed(data []byte) {
	var msg dnsmessage.Msg
	err := msg.Unpack(data)
	if err != nil {
		log.Warnf("Failed to unpack dns resp, stream: %v, err: %v, data: %v", m.stream, err, data)
		return
	}
	conn, ok := m.recvMap.Load(msg.Id)
	if !ok {
		log.Debugf("Unknown dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(chan *dnsmessage.Msg) <- &msg:
		// OK
	default:
		log.Debugf("Drop dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		// Channel full, drop the message
	}
}

func (m *DnsManager) Close() error {
	m.cancel()
	return m.conn.Close()
}

func (m *DnsManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func (m *DnsManager) Resolve(ctx context.Context, msg *dnsmessage.Msg) error {
	origMsgId := msg.Id
	msg.Id = uint16(fastrand.Intn(math.MaxUint16))
	defer func() { msg.Id = origMsgId }()
	buf := pool.GetBuffer(1024)
	defer pool.PutBuffer(buf)
	var data []byte
	var err error
	if m.stream {
		if data, err = msg.PackBuffer(buf[2:]); err == nil {
			dataLen := uint16(len(data))
			binary.BigEndian.PutUint16(buf, dataLen)
			data = buf[:dataLen+2]
		}
	} else {
		data, err = msg.PackBuffer(buf)
	}
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	recvCh := make(chan *dnsmessage.Msg, 1)
	m.recvMap.Store(msg.Id, recvCh)
	defer m.recvMap.Delete(msg.Id)

	timer := time.NewTimer(dnsRetryInterval)
	defer timer.Stop()

	for i := range dnsRetryCount {
		if _, err := m.conn.Write(data); err != nil {
			return err
		}
		if i > 0 {
			timer.Reset(dnsRetryInterval)
		}
		select {
		case <-m.ctx.Done():
			return net.ErrClosed
		case <-ctx.Done():
			return context.Canceled
		case recvMsg := <-recvCh:
			*msg = *recvMsg
			return nil
		case <-timer.C:
		}
	}

	var qname string
	var qtype uint16
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = msg.Question[0].Qtype
	}
	log.Warnf("dns timeout, stream: %v, qname: %v, qtype: %v", m.stream, qname, qtype)
	return context.DeadlineExceeded
}
