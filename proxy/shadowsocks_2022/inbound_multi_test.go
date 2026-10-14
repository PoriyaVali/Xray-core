package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	XBuf "github.com/xtls/xray-core/common/buf"
	XNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const multiTestServerKey = "server-key-16byt"

var multiTestDispatchStopped = errors.New("test dispatcher stopped")

type multiTestDispatcher struct {
	users   chan *protocol.MemoryUser
	echoUDP bool
	links   chan *multiTestEchoLink
}

func (d *multiTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *multiTestDispatcher) Start() error      { return nil }
func (d *multiTestDispatcher) Close() error      { return nil }
func (d *multiTestDispatcher) Dispatch(ctx context.Context, dest XNet.Destination) (*transport.Link, error) {
	d.users <- session.InboundFromContext(ctx).User
	if d.echoUDP && dest.Network == XNet.Network_UDP {
		link := &multiTestEchoLink{packets: make(chan XBuf.MultiBuffer, 4), done: make(chan struct{})}
		d.links <- link
		return &transport.Link{Reader: link, Writer: link}, nil
	}
	return nil, multiTestDispatchStopped
}
func (d *multiTestDispatcher) DispatchLink(context.Context, XNet.Destination, *transport.Link) error {
	return multiTestDispatchStopped
}

func multiTestUser(email, key string) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{Key: base64.StdEncoding.EncodeToString([]byte(key))}}
}

func newMultiTestInbound(t *testing.T, users ...*protocol.MemoryUser) *MultiUserInbound {
	t.Helper()
	config := &MultiUserServerConfig{
		Method: "2022-blake3-aes-128-gcm",
		Key:    base64.StdEncoding.EncodeToString([]byte(multiTestServerKey)),
	}
	for _, user := range users {
		config.Users = append(config.Users, protocol.ToProtoUser(user))
	}
	inbound, err := NewMultiServer(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return inbound
}

func multiTestContext(d *multiTestDispatcher) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
	return session.ContextWithDispatcher(ctx, d)
}

// Pause a real encrypted handshake after credential authentication, before the
// inbound callback. Removing/reindexing users at that exact point previously
// changed the identity of the admitted connection or panicked.
func TestMultiUserEncryptedHandshakeIdentitySurvivesReindex(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint("remove_authenticated=", removed), func(t *testing.T) {
			a := multiTestUser("first@example", "first-user-key16")
			b := multiTestUser("second@example", "second-user-key1")
			inbound := newMultiTestInbound(t, a, b)
			selected := inbound.GetUser(context.Background(), b.Email)
			if removed {
				selected = inbound.GetUser(context.Background(), a.Email)
			}
			method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm",
				base64.StdEncoding.EncodeToString([]byte(multiTestServerKey))+":"+selected.Account.(*MemoryAccount).Key, nil)
			if err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			authenticated, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			d := &multiTestDispatcher{users: make(chan *protocol.MemoryUser, 1)}
			result := make(chan error, 1)
			go func() {
				defer func() {
					if value := recover(); value != nil {
						result <- fmt.Errorf("inbound panic: %v", value)
					}
				}()
				result <- inbound.service.NewConnection0(multiTestContext(d), server, M.Metadata{}, server, func() {
					close(authenticated)
					<-release
				})
			}()
			write := make(chan error, 1)
			go func() {
				conn := method.DialEarlyConn(client, M.ParseSocksaddr("127.0.0.1:12345"))
				_, err := conn.Write([]byte("real SS2022 encrypted request"))
				write <- err
			}()
			select {
			case <-authenticated:
			case err := <-result:
				t.Fatalf("authentication failed before pause: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("authentication pause timed out")
			}
			if err := inbound.RemoveUser(context.Background(), a.Email); err != nil {
				t.Fatal(err)
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-result:
				if removed {
					if errors.Is(err, multiTestDispatchStopped) {
						t.Fatal("removed credentials reached the dispatcher")
					}
					if err == nil {
						t.Fatal("removed credentials were admitted")
					}
				} else if !errors.Is(err, multiTestDispatchStopped) {
					t.Fatalf("surviving user was not dispatched safely: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("inbound callback timed out")
			}
			select {
			case user := <-d.users:
				if removed {
					t.Fatalf("removed user was attributed to %q", user.Email)
				}
				if user != selected {
					t.Fatalf("authenticated user changed from %q to %q", selected.Email, user.Email)
				}
			default:
				if !removed {
					t.Fatal("surviving user was not routed")
				}
			}
			_ = server.Close()
			select {
			case <-write:
			case <-time.After(5 * time.Second):
				t.Fatal("client writer did not stop")
			}
		})
	}
}

func TestMultiUserInvalidAddIsTransactional(t *testing.T) {
	inbound := newMultiTestInbound(t, multiTestUser("valid@example", "valid-user-key16"))
	original := inbound.GetUser(context.Background(), "valid@example")
	bad := &protocol.MemoryUser{Email: "invalid@example", Account: &MemoryAccount{Key: "not-base64"}}
	if err := inbound.AddUser(context.Background(), bad); err == nil {
		t.Fatal("invalid credential update succeeded")
	}
	if got := inbound.GetUsers(context.Background()); len(got) != 1 || got[0] != original {
		t.Fatalf("failed update mutated membership: %v", got)
	}
}

func TestMultiUserInvalidAccountAndDuplicateEmail(t *testing.T) {
	inbound := newMultiTestInbound(t, multiTestUser("Valid@Example", "valid-user-key16"))
	for _, bad := range []*protocol.MemoryUser{
		nil,
		{Email: "missing-account@example"},
		{Email: "nil-account@example", Account: (*MemoryAccount)(nil)},
		multiTestUser("valid@example", "other-user-key16"),
	} {
		if err := inbound.AddUser(context.Background(), bad); err == nil {
			t.Fatal("invalid account or duplicate email was accepted")
		}
		if inbound.GetUsersCount(context.Background()) != 1 {
			t.Fatal("rejected update changed membership")
		}
	}
}

func TestMultiUserInvalidRemoveIsTransactional(t *testing.T) {
	inbound := newMultiTestInbound(t, multiTestUser("first@example", "first-user-key16"), multiTestUser("remaining@example", "other-user-key16"))
	remaining := inbound.GetUser(context.Background(), "remaining@example")
	remaining.Account.(*MemoryAccount).Key = "not-base64"
	if err := inbound.RemoveUser(context.Background(), "first@example"); err == nil {
		t.Fatal("invalid credential update succeeded")
	}
	if inbound.GetUsersCount(context.Background()) != 2 || inbound.GetUser(context.Background(), "first@example") == nil {
		t.Fatal("failed removal mutated membership")
	}
}

// UDP callbacks must carry the authenticated identity, never its former slice
// position. A removed identity must not become a subsequently added user.
func TestMultiUserUDPIdentityAndRemoval(t *testing.T) {
	a := multiTestUser("first@example", "first-user-key16")
	b := multiTestUser("second@example", "second-user-key1")
	inbound := newMultiTestInbound(t, a, b)
	first := inbound.GetUser(context.Background(), a.Email)
	second := inbound.GetUser(context.Background(), b.Email)
	if err := inbound.RemoveUser(context.Background(), a.Email); err != nil {
		t.Fatal(err)
	}
	if err := inbound.AddUser(context.Background(), multiTestUser("replacement@example", "third-user-key16")); err != nil {
		t.Fatal(err)
	}
	d := &multiTestDispatcher{users: make(chan *protocol.MemoryUser, 1)}
	metadata := M.Metadata{Destination: M.ParseSocksaddr("127.0.0.1:12345")}
	ctx := A.ContextWithUser(multiTestContext(d), second)
	if err := inbound.NewPacketConnection(ctx, nil, metadata); !errors.Is(err, multiTestDispatchStopped) {
		t.Fatalf("surviving UDP user rejected: %v", err)
	}
	if user := <-d.users; user != second {
		t.Fatalf("UDP identity changed to %q", user.Email)
	}
	ctx = A.ContextWithUser(multiTestContext(d), first)
	if err := inbound.NewPacketConnection(ctx, nil, metadata); err == nil || errors.Is(err, multiTestDispatchStopped) {
		t.Fatalf("removed UDP identity reached dispatcher: %v", err)
	}
	select {
	case user := <-d.users:
		t.Fatalf("removed UDP identity was attributed to %q", user.Email)
	default:
	}
	if err := inbound.AddUser(context.Background(), multiTestUser(a.Email, "fresh-user-key16")); err != nil {
		t.Fatal(err)
	}
	if err := inbound.NewPacketConnection(ctx, nil, metadata); err == nil || errors.Is(err, multiTestDispatchStopped) {
		t.Fatalf("retired generation became a newly added user: %v", err)
	}
	if err := inbound.NewPacketConnection(multiTestContext(d), nil, metadata); err == nil || errors.Is(err, multiTestDispatchStopped) {
		t.Fatalf("unauthenticated UDP callback reached dispatcher: %v", err)
	}
}

type multiTestEchoLink struct {
	packets chan XBuf.MultiBuffer
	done    chan struct{}
	once    sync.Once
}

func (l *multiTestEchoLink) ReadMultiBuffer() (XBuf.MultiBuffer, error) {
	select {
	case packet := <-l.packets:
		return packet, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *multiTestEchoLink) WriteMultiBuffer(packet XBuf.MultiBuffer) error {
	select {
	case l.packets <- packet:
		return nil
	case <-l.done:
		XBuf.ReleaseMulti(packet)
		return net.ErrClosed
	}
}

func (l *multiTestEchoLink) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Exercise real encrypted TCP authentication plus a single live encrypted UDP
// session while user-table generations are published. Recreating the service
// during reload would reset the UDP replay window/session writer and break this.
func TestMultiUserConcurrentEncryptedTCPAndPersistentUDP(t *testing.T) {
	target := multiTestUser("target@example", "target-user-key1")
	inbound := newMultiTestInbound(t, multiTestUser("first@example", "first-user-key16"), target)
	target = inbound.GetUser(context.Background(), target.Email)
	if err := inbound.RemoveUser(context.Background(), "first@example"); err != nil {
		t.Fatal(err)
	}
	method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm",
		base64.StdEncoding.EncodeToString([]byte(multiTestServerKey))+":"+target.Account.(*MemoryAccount).Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	d := &multiTestDispatcher{users: make(chan *protocol.MemoryUser, 512), echoUDP: true, links: make(chan *multiTestEchoLink, 8)}
	packetConn := bufio.NewPacketConn(server)
	packetErrors := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			packet := B.NewPacket()
			source, err := packetConn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				return
			}
			err = inbound.service.NewPacket(multiTestContext(d), packetConn, packet, M.Metadata{Source: source})
			if err != nil {
				packet.Release()
				packetErrors <- err
				return
			}
		}
	}()
	defer func() {
		_ = server.Close()
		<-serverDone
		for len(d.links) > 0 {
			_ = (<-d.links).Close()
		}
	}()
	raw, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	udp := method.DialPacketConn(raw)
	defer udp.Close()
	payload := []byte("same SS2022 UDP session across Xray user reloads")
	roundtrip := func() {
		t.Helper()
		_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := udp.WriteTo(payload, M.ParseSocksaddr("127.0.0.1:12345")); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2048)
		n, _, err := udp.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("persistent encrypted UDP echo: %v", err)
		}
		if !bytes.Equal(buffer[:n], payload) {
			t.Fatal("UDP payload changed")
		}
	}
	roundtrip()
	var tcpCount atomic.Int64
	tcpErrors := make(chan error, 1)
	tcpDone := make(chan struct{})
	go func() {
		defer close(tcpDone)
		for loop := 0; loop < 100; loop++ {
			server, client := net.Pipe()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			result := make(chan error, 1)
			go func() {
				result <- inbound.service.NewConnection0(multiTestContext(d), server, M.Metadata{}, server, nil)
			}()
			conn := method.DialEarlyConn(client, M.ParseSocksaddr("127.0.0.1:12345"))
			_, writeErr := conn.Write([]byte("encrypted handshake during reload"))
			if writeErr != nil {
				_ = server.Close()
				_ = client.Close()
				<-result
				tcpErrors <- writeErr
				return
			}
			err := <-result
			_ = server.Close()
			_ = client.Close()
			if !errors.Is(err, multiTestDispatchStopped) {
				tcpErrors <- err
				return
			}
			tcpCount.Add(1)
		}
	}()
	defer func() { <-tcpDone }()
	for loop := 0; loop < 100; loop++ {
		churn := multiTestUser("churn@example", "churn-user-key16")
		if err := inbound.AddUser(context.Background(), churn); err != nil {
			t.Fatal(err)
		}
		roundtrip()
		if err := inbound.RemoveUser(context.Background(), churn.Email); err != nil {
			t.Fatal(err)
		}
		roundtrip()
		_ = inbound.GetUsers(context.Background())
	}
	<-tcpDone
	select {
	case err := <-tcpErrors:
		t.Fatalf("encrypted TCP authentication interrupted: %v", err)
	default:
	}
	select {
	case err := <-packetErrors:
		t.Fatalf("encrypted UDP session interrupted: %v", err)
	default:
	}
	if tcpCount.Load() != 100 {
		t.Fatalf("completed %d TCP handshakes, want 100", tcpCount.Load())
	}
	if len(d.links) != 1 {
		t.Fatalf("UDP session was recreated %d times", len(d.links))
	}
	for len(d.users) > 0 {
		if user := <-d.users; user != target {
			t.Fatalf("traffic billed to wrong identity %q", user.Email)
		}
	}
	t.Log("100 encrypted TCP handshakes and 201 exchanges on one UDP session preserved identity during 200 user-table updates")
}
