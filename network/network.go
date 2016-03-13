// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package network

import (
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/subnet"
)

const (
	renewMargin = time.Hour
)

var (
	errInterrupted = errors.New("interrupted")
	errCanceled = errors.New("canceled")
)

//
// Network 是 flannel中最核心的环节
//
type Network struct {
	Name       string
	Config     *subnet.Config

	ctx        context.Context
	cancelFunc context.CancelFunc

	sm         subnet.Manager  // 通过 registry 的管理，来实现了subnet的lease的管理
	bm         backend.Manager // 和udp等相关

	ipMasq     bool
	bn         backend.Network
}

func NewNetwork(ctx context.Context, sm subnet.Manager, bm backend.Manager, name string, ipMasq bool) *Network {
	ctx, cf := context.WithCancel(ctx)

	return &Network{
		Name:       name,
		sm:         sm,
		bm:         bm,
		ipMasq:     ipMasq,
		ctx:        ctx,
		cancelFunc: cf,
	}
}

func wrapError(desc string, err error) error {
	if err == context.Canceled {
		return err
	}
	return fmt.Errorf("failed to %v: %v", desc, err)
}


//
// 如何初始化呢?
//
func (n *Network) init() error {
	var err error

	// 1. 通过: Registry获取网络的配置
	n.Config, err = n.sm.GetNetworkConfig(n.ctx, n.Name)
	if err != nil {
		return wrapError("retrieve network config", err)
	}

	// 2. 获取BackendType, 例如: udp
	be, err := n.bm.GetBackend(n.Config.BackendType)
	if err != nil {
		return wrapError("create and initialize network", err)
	}

	// 3. 注册网络
	n.bn, err = be.RegisterNetwork(n.ctx, n.Name, n.Config)
	if err != nil {
		return wrapError("register network", err)
	}

	// 4. 修改Node的iptables
	if n.ipMasq {
		err = setupIPMasq(n.Config.Network)
		if err != nil {
			return wrapError("set up IP Masquerade", err)
		}
	}

	return nil
}

// 不停地重试，直到 init  完成
func (n *Network) retryInit() error {
	for {
		err := n.init()
		if err == nil || err == context.Canceled {
			return err
		}

		log.Error(err)

		select {
		case <-n.ctx.Done():
			return n.ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (n *Network) runOnce(extIface *backend.ExternalInterface, inited func(bn backend.Network)) error {
	// 1. 初始化
	if err := n.retryInit(); err != nil {
		return errCanceled
	}

	// 2. 回调inited的函数，例如写入: /run/flannel/subnet.env, 然后再启动 Docker
	inited(n.bn)

	ctx, interruptFunc := context.WithCancel(n.ctx)

	wg := sync.WaitGroup{}

	// 任务1: bn继续自己正常的工作
	wg.Add(1)
	go func() {
		n.bn.Run(ctx)
		wg.Done()
	}()

	evts := make(chan subnet.Event)

	// 任务2: bn继续自己正常的工作
	wg.Add(1)
	go func() {
		// Watch Lease是干什么用的呢？
		subnet.WatchLease(ctx, n.sm, n.Name, n.bn.Lease().Subnet, evts)
		wg.Done()
	}()

	// 恢复: iptables的修改
	defer func() {
		if n.ipMasq {
			if err := teardownIPMasq(n.Config.Network); err != nil {
				log.Errorf("Failed to tear down IP Masquerade for network %v: %v", n.Name, err)
			}
		}
	}()

	defer wg.Wait()

	dur := n.bn.Lease().Expiration.Sub(time.Now()) - renewMargin
	for {
		select {
		// 不停地续约，如果自己挂了，续约就结束
		// 只有不停地续约才能证明自己活着
		case <-time.After(dur):
			err := n.sm.RenewLease(n.ctx, n.Name, n.bn.Lease())
			if err != nil {
				log.Error("Error renewing lease (trying again in 1 min): ", err)
				dur = time.Minute
				continue
			}

			log.Info("Lease renewed, new expiration: ", n.bn.Lease().Expiration)
			dur = n.bn.Lease().Expiration.Sub(time.Now()) - renewMargin

		case e := <-evts:
			switch e.Type {
			case subnet.EventAdded:
				n.bn.Lease().Expiration = e.Lease.Expiration
				dur = n.bn.Lease().Expiration.Sub(time.Now()) - renewMargin

			case subnet.EventRemoved:
				log.Warning("Lease has been revoked")
				interruptFunc()
				return errInterrupted
			}

		case <-n.ctx.Done():
			return errCanceled
		}
	}
}

func (n *Network) Run(extIface *backend.ExternalInterface, inited func(bn backend.Network)) {
	for {
		// 永远运行下去，如果是: Interrupted, 那么继续；否则关闭
		switch n.runOnce(extIface, inited) {
		case errInterrupted:

		case errCanceled:
			return
		default:
			panic("unexpected error returned")
		}
	}
}

func (n *Network) Cancel() {
	n.cancelFunc()
}
