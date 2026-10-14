package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*MultiUserServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiServer(ctx, config.(*MultiUserServerConfig))
	}))
}

type MultiUserInbound struct {
	sync.RWMutex
	networks []net.Network
	users    []*protocol.MemoryUser
	active   map[*protocol.MemoryUser]struct{}
	service  *shadowaead_2022.MultiService[*protocol.MemoryUser]
}

func NewMultiServer(ctx context.Context, config *MultiUserServerConfig) (*MultiUserInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}
	memUsers := []*protocol.MemoryUser{}
	for i, user := range config.Users {
		if user == nil {
			return nil, errors.New("missing shadowsocks user")
		}
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(i) + "-" + u.String()
		}
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get shadowsocks user").Base(err).AtError()
		}
		memUsers = append(memUsers, u)
	}

	inbound := &MultiUserInbound{
		networks: networks,
	}
	if config.Key == "" {
		return nil, errors.New("missing key")
	}
	psk, err := base64.StdEncoding.DecodeString(config.Key)
	if err != nil {
		return nil, errors.New("parse config").Base(err)
	}
	service, err := shadowaead_2022.NewMultiService[*protocol.MemoryUser](config.Method, psk, 500, inbound, nil)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}
	inbound.service = service
	if err := inbound.updateUsersLocked(memUsers); err != nil {
		return nil, errors.New("create service").Base(err)
	}
	return inbound, nil
}

// Publish credentials and membership as one transaction. Authentication uses
// the MemoryUser itself rather than an index that removal can assign to someone
// else. Callback admission takes the same lock and cannot observe a half update.
// The existing service and its UDP sessions remain intact across updates.
func (i *MultiUserInbound) updateUsersLocked(users []*protocol.MemoryUser) error {
	passwords := make([]string, len(users))
	active := make(map[*protocol.MemoryUser]struct{}, len(users))
	for index, user := range users {
		if user == nil {
			return errors.New("missing shadowsocks user")
		}
		account, ok := user.Account.(*MemoryAccount)
		if !ok || account == nil {
			return errors.New("invalid shadowsocks account")
		}
		passwords[index] = account.Key
		active[user] = struct{}{}
	}
	if err := i.service.UpdateUsersWithPasswords(users, passwords); err != nil {
		return errors.New("update shadowsocks users").Base(err)
	}
	i.users = users
	i.active = active
	return nil
}

func (i *MultiUserInbound) authenticatedUser(ctx context.Context) (*protocol.MemoryUser, error) {
	user, ok := A.UserFromContext[*protocol.MemoryUser](ctx)
	if !ok || user == nil {
		return nil, errors.New("missing authenticated shadowsocks user")
	}
	i.RLock()
	_, active := i.active[user]
	i.RUnlock()
	if !active {
		return nil, errors.New("authenticated shadowsocks user was removed")
	}
	return user, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (i *MultiUserInbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.Lock()
	defer i.Unlock()

	if u == nil {
		return errors.New("missing shadowsocks user")
	}
	if u.Email != "" {
		for idx := range i.users {
			if strings.EqualFold(i.users[idx].Email, u.Email) {
				return errors.New("User ", u.Email, " already exists.")
			}
		}
	}
	users := make([]*protocol.MemoryUser, len(i.users)+1)
	copy(users, i.users)
	users[len(i.users)] = u
	return i.updateUsersLocked(users)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *MultiUserInbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	i.Lock()
	defer i.Unlock()

	idx := -1
	for ii, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			idx = ii
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}

	ulen := len(i.users)

	users := make([]*protocol.MemoryUser, ulen-1)
	copy(users, i.users[:ulen-1])
	if idx < ulen-1 {
		users[idx] = i.users[ulen-1]
	}
	return i.updateUsersLocked(users)
}

// GetUser implements proxy.UserManager.GetUser().
func (i *MultiUserInbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	i.RLock()
	defer i.RUnlock()

	for _, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (i *MultiUserInbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	i.RLock()
	defer i.RUnlock()
	dst := make([]*protocol.MemoryUser, len(i.users))
	copy(dst, i.users)
	return dst
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (i *MultiUserInbound) GetUsersCount(context.Context) int64 {
	i.RLock()
	defer i.RUnlock()
	return int64(len(i.users))
}

func (i *MultiUserInbound) Network() []net.Network {
	return i.networks
}

func (i *MultiUserInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-multi"
	inbound.CanSpliceCopy = 3

	var metadata M.Metadata
	if inbound.Source.IsValid() {
		metadata.Source = M.ParseSocksaddr(inbound.Source.NetAddr())
	}

	ctx = session.ContextWithDispatcher(ctx, dispatcher)

	if network == net.Network_TCP {
		return singbridge.ReturnError(i.service.NewConnection(ctx, connection, metadata))
	} else {
		reader := buf.NewReader(connection)
		pc := &natPacketConn{connection}
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				return singbridge.ReturnError(err)
			}
			for _, buffer := range mb {
				packet := B.As(buffer.Bytes()).ToOwned()
				buffer.Release()
				err = i.service.NewPacket(ctx, pc, packet, metadata)
				if err != nil {
					packet.Release()
					buf.ReleaseMulti(mb)
					return err
				}
			}
		}
	}
}

func (i *MultiUserInbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	user, err := i.authenticatedUser(ctx)
	if err != nil {
		return err
	}
	inbound := session.InboundFromContext(ctx)
	inbound.User = user
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to tcp:", metadata.Destination)
	dispatcher := session.DispatcherFromContext(ctx)
	destination, err := singbridge.ToDestination(metadata.Destination, net.Network_TCP)
	if err != nil {
		return err
	}
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	return singbridge.CopyConn(ctx, conn, link, conn)
}

func (i *MultiUserInbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	user, err := i.authenticatedUser(ctx)
	if err != nil {
		return err
	}
	inbound := session.InboundFromContext(ctx)
	inbound.User = user
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to udp:", metadata.Destination)
	dispatcher := session.DispatcherFromContext(ctx)
	destination, err := singbridge.ToDestination(metadata.Destination, net.Network_UDP)
	if err != nil {
		return err
	}
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		T: signal.CancelAfterInactivity(ctx, func() {
			common.Interrupt(link.Reader)
		}, 300*time.Second),
	}
	return bufio.CopyPacketConn(ctx, conn, outConn)
}

func (i *MultiUserInbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	errors.LogWarning(ctx, err.Error())
}
