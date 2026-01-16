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
	go func() {
		if err := m.run(); err != nil {
			log.WithError(err).Error("DNS manager recv loop exited")
		}
	}()
	return m
}

func (m *DnsManager) run() error {
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		var data []byte
		var err error
		if data, err = m.read(buf); err != nil {
			m.Close()
			return err
		}
		m.feed(data)
	}
}

func (m *DnsManager) read(buf []byte) (data []byte, err error) {
	if m.stream {
		msgLenBuf := buf[:2]
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, msgLenBuf); err != nil {
			return nil, oops.Wrapf(err, "failed to read DNS resp payload length")
		}
		msgLen := int(binary.BigEndian.Uint16(msgLenBuf))
		if msgLen > len(buf) {
			return nil, oops.Errorf("dns msg len too large: %d > %d", msgLen, len(buf))
		}
		data = buf[:msgLen]
		if _, err = io.ReadFull(m.conn, data); err != nil {
			return nil, oops.Wrapf(err, "failed to read DNS resp payload")
		}
	} else {
		var n int
		if n, err = m.conn.Read(buf); err != nil {
			return nil, oops.Wrapf(err, "failed to read DNS resp payload")
		}
		data = buf[:n]
	}
	return data, nil
}

func (m *DnsManager) feed(data []byte) {
	var msg dnsmessage.Msg
	err := msg.Unpack(data)
	if err != nil {
		log.Warnf("Failed to unpack dns resp, err: %v, data: %v", err, data)
		return
	}
	conn, ok := m.recvMap.Load(msg.Id)
	if !ok {
		log.Warnf("Unknown dns resp msg, id: %v", msg.Id)
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(chan *dnsmessage.Msg) <- &msg:
		// OK
	default:
		log.Warnf("Drop dns resp msg, id: %v", msg.Id)
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

func (m *DnsManager) Resolve(msg *dnsmessage.Msg) error {
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

	timer := time.NewTimer(consts.DefaultDNSRetryInterval)
	defer timer.Stop()

	for i := range consts.DefaultDNSRetryCount {
		if _, err := m.conn.Write(data); err != nil {
			return err
		}
		if i > 0 {
			timer.Reset(consts.DefaultDNSRetryInterval)
		}
		select {
		case <-m.ctx.Done():
			return net.ErrClosed
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
	log.Warnf("dns timeout, qname: %v, qtype: %v", qname, qtype)
	return context.DeadlineExceeded
}
