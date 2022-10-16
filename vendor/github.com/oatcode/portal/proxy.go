// Package portal provides the ability to build a 2-node HTTP tunnel
package portal

import (
	"context"
	fmt "fmt"
	"io"
	"math"
	"net"
	"strings"

	"github.com/oatcode/portal/pkg/message"
	"google.golang.org/protobuf/proto"
)

/*
This is a 2-node HTTP tunnel proxy
The main goal is to provide access from cloud to on-prem without opening ports on-prem.
This proxy has two sides: tunnel client and tunnel server
On-prem running tunnel client will connect to tunnel server running in cloud.
Proxy port can be opened on cloud side to allow access to on-prem via HTTP tunnelling:
  https://en.wikipedia.org/wiki/HTTP_tunnel
Proxy listens to incoming tunneling request and interact with the remote side
A mapper keeps keep track of remote/local initiated connections separately to prevent ID conflicts

Generate protobuf file with:
  protoc --proto_path=pkg/message --go_out=. pkg/message/message.proto

Appreviations used in code:
ich = tunnel input channel
och = tunnel output channel
coch = connect operation channel for processing HTTP CONNECT
pch = proxy writer channel
co = command

The close sequence for sides s1 and s2
s1 proxy-reader: read error. send disconnect to tunnel
s2 mapper: recv disconnect. remove mapping. send to proxy-writer
s2 proxy-writer: recv disconnect. close socket.
s2 proxy-reader: read error (as writer closed it). send disconnect to tunnel
s1 mapper: recv disconnect. remove mapping. send to proxy-writer
s1 proxy-writer: recv disconnect. close socket

Flow
C  = Client
PL = Proxy Listener
TS = Tunnel Server
TC = Tunnel Client
PC = Proxy Connector
S  = Server
PR = Proxy Reader
PW = Proxy Writer

+------+          +------+          +------+            +------+          +------+          +------+
|      |          |      |          |      |            |      |          |      |          |      |
|  C   |----------|  PL  |----------|  TS  |------------|  TC  |----------|  PC  |----------|  S   |
|      |          |      |          |      |            |      |          |      |          |      |
+------+          +------+          +------+            +------+          +------+          +------+


+------+          +------+          +------+            +------+          +------+          +------+
|      |----------|  PR  |----------|      |            |      |----------|  PR  |----------|      |
|  C   |          +------+          |  TS  |------------|  TC  |          +------+          |  S   |
|      |----------|  PW  |----------|      |            |      |----------|  PW  |----------|      |
+------+          +------+          +------+            +------+          +------+          +------+

Note
- Proxy can also run on tunnel client side or both
- HTTP Connector on remote side will return 503 for any connection error
*/

// ConnectOperation is for handling HTTP CONNECT request
type ConnectOperation struct {
	// Hijacked HTTP connection for CONNECT method
	// or a connection with HTTP CONNECT processed
	Conn net.Conn

	// Address section from the HTTP CONNECT line
	Address string
}

// Framer is for reading and writing messages with boundaries (i.e. frame)
type Framer interface {
	// Read reads a message from the connection
	// The returned byte array is of the exact length of the message
	Read() (b []byte, err error)

	// Write writes the entire byte array as a message to the connection
	Write(b []byte) error

	// Close closes the connection
	// Error maybe used by the underlying connection protocol
	Close(err error) error
}

var (
	// Logf is for setting logging function
	Logf func(string, ...interface{})
)

type key int

const (
	connectKey key = iota
	bufferSize     = 2048
)

func connString(c net.Conn) string {
	return fmt.Sprintf("%v->%v", c.LocalAddr(), c.RemoteAddr())
}

func logf(fmt string, v ...interface{}) {
	if Logf != nil {
		Logf(fmt, v...)
	}
}

func proxyWriter(c net.Conn, pch <-chan *message.Message, id int32) {
	logf("proxyWriter starts. id=%d conn=%s", id, connString(c))
	defer func() {
		logf("proxyWriter ends. id=%d conn=%s", id, connString(c))
		c.Close()
	}()
	for co := range pch {
		if co.Type == message.Message_HTTP_CONNECT_OK {
			c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			logf("proxyWriter connected. id=%d conn=%s", id, connString(c))
		} else if co.Type == message.Message_HTTP_SERVICE_UNAVAILABLE {
			c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
			logf("proxyWriter service unavailable. id=%d conn=%s", id, connString(c))
			return
		} else if co.Type == message.Message_DISCONNECTED {
			logf("proxyWriter disconnected. id=%d conn=%s", id, connString(c))
			return
		} else if co.Type == message.Message_DATA {
			c.Write(co.Buf)
		}
	}
}

// proxyReader uses the origin to denote if it is handling a local initiated connection or a remote one
func proxyReader(c net.Conn, och chan<- *message.Message, id int32, origin message.Message_Origin) {
	logf("proxyReader starts. id=%d conn=%s", id, connString(c))
	defer logf("proxyReader ends. id=%d conn=%s", id, connString(c))
	for {
		buf := make([]byte, bufferSize)
		len, err := c.Read(buf)
		if err != nil {
			if err == io.EOF {
				logf("proxyReader local disconnected. id=%d conn=%s", id, connString(c))
			} else if strings.Contains(err.Error(), "use of closed network connection") {
				logf("proxyReader remote disconnected. id=%d conn=%s", id, connString(c))
			} else {
				logf("proxyReader read error. id=%d conn=%s err=%v", id, connString(c), err)
			}

			co := &message.Message{
				Type:   message.Message_DISCONNECTED,
				Origin: origin,
				Id:     id,
			}
			och <- co
			return
		}

		co := &message.Message{
			Type:   message.Message_DATA,
			Origin: origin,
			Id:     id,
			Buf:    buf[0:len],
		}
		och <- co
	}
}

func proxyConnector(sa string, och chan<- *message.Message, pch <-chan *message.Message, id int32) {
	logf("proxyConnector connecting. id=%d sa=%s", id, sa)
	c, err := net.Dial("tcp", sa)
	if err != nil {
		co := &message.Message{
			Type: message.Message_HTTP_SERVICE_UNAVAILABLE,
			Id:   id,
		}
		och <- co
		logf("proxyConnector connect error. id=%d sa=%s err=%v", id, sa, err)
		return
	}
	logf("proxyConnector connected. id=%d conn=%s", id, connString(c))

	go proxyWriter(c, pch, id)
	go proxyReader(c, och, id, message.Message_ORIGIN_REMOTE)

	co := &message.Message{
		Type: message.Message_HTTP_CONNECT_OK,
		Id:   id,
	}
	och <- co
}

// Requires 2 maps to differenciate local and remote originated connections
//   lm is local channel map
//   rm is remote channel map
// Connection map is only used until connection is connected
//   lcm is local connection map
func mapper(ich <-chan *message.Message, coch <-chan ConnectOperation, och chan<- *message.Message) {
	logf("mapper starts")
	defer logf("mapper ends")

	var id int32
	lm := make(map[int32]chan<- *message.Message)
	rm := make(map[int32]chan<- *message.Message)
	lcm := make(map[int32]net.Conn)
	defer func() {
		// Channel closed. Clear connections
		for _, ch := range lm {
			close(ch)
		}
		for _, ch := range rm {
			close(ch)
		}
	}()

	for {
		select {
		case i, ok := <-ich:
			if !ok {
				return
			}
			// From remote
			if i.Type == message.Message_HTTP_CONNECT {
				// Remote initiated
				pch := make(chan *message.Message)
				rm[i.Id] = pch
				go proxyConnector(i.SocketAddress, och, pch, i.Id)
			} else if i.Type == message.Message_HTTP_CONNECT_OK {
				// Local initiated
				c := lcm[i.Id]
				delete(lcm, i.Id)
				go proxyReader(c, och, i.Id, message.Message_ORIGIN_LOCAL)
				pch := lm[i.Id]
				pch <- i
			} else if i.Type == message.Message_HTTP_SERVICE_UNAVAILABLE {
				// Local initiated
				delete(lcm, i.Id)
				pch := lm[i.Id]
				delete(lm, i.Id)
				pch <- i
			} else {
				var m map[int32]chan<- *message.Message
				if i.Origin == message.Message_ORIGIN_LOCAL {
					// Received from other side with local origin. Use remote map
					m = rm
				} else {
					m = lm
				}
				pch := m[i.Id]
				if i.Type == message.Message_DISCONNECTED {
					delete(m, i.Id)
				}
				pch <- i
			}
		case co := <-coch:
			// Find next available id
			used := true
			for i := int32(0); i < math.MaxInt32; i++ {
				if _, used = lm[id+i]; !used {
					id = id + i
					break
				}
			}
			if used {
				logf("Too many connections")
				return
			}
			// New connection from local
			lcm[id] = co.Conn
			pch := make(chan *message.Message)
			lm[id] = pch
			go proxyWriter(co.Conn, pch, id)

			och <- &message.Message{
				Type:          message.Message_HTTP_CONNECT,
				Id:            id,
				SocketAddress: co.Address,
			}
			id++
		}
	}
}

// Send data to the other side of the tunnel
func tunnelWriter(ctx context.Context, c Framer, och <-chan *message.Message) {
	logf("tunnelWriter starts")
	defer logf("tunnelWriter ends")
	for {
		select {
		case co, ok := <-och:
			if !ok {
				logf("tunnelWriter channel closed")
				return
			}
			var data []byte
			data, err := proto.Marshal(co)
			if err != nil {
				logf("tunnelWriter marshal error: %v", err)
				return
			}
			if err = c.Write(data); err != nil {
				logf("tunnelWriter write error: %v", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// Read commands comming from the other side of the tunnel
func tunnelReader(c Framer, ich chan<- *message.Message) {
	logf("tunnelReader starts")
	defer logf("tunnelReader ends")
	var err error
	var buf []byte
	for {
		buf, err = c.Read()
		if err != nil {
			break
		}
		co := &message.Message{}
		if err = proto.Unmarshal(buf, co); err != nil {
			break
		}
		ich <- co
	}
	if err == io.EOF {
		logf("tunnelReader disconnected")
	} else {
		logf("tunnelReader error: %v", err)
	}
	c.Close(err)
}

// TunnelServe starts the communication with the remote side with tunnel messages connection c.
// It handles new proxy connections coming into connection channel cch.
func TunnelServe(ctx context.Context, c Framer, coch <-chan ConnectOperation) {
	logf("TunnelServe starts")
	defer logf("TunnelServe ends")

	ich := make(chan *message.Message)
	och := make(chan *message.Message)

	if coch == nil {
		// Create an unused coch for mapper
		coch = make(<-chan ConnectOperation)
	}

	ctx = context.WithValue(ctx, connectKey, c)

	go mapper(ich, coch, och)
	go tunnelWriter(ctx, c, och)
	// This blocks until connection closed
	tunnelReader(c, ich)

	close(ich)
	// Don't close och, as mapper may still use it. Let GC takes care of it.
	// Don't close coch, as proxyConnect may still use it. Let GC takes care of it.
}
