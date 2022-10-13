// Copyright (c) 2020-2021 Doc.ai and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/networkservicemesh/sdk/pkg/registry/common/dnsresolve"
)

// FakeDNSResolver implements the dnsresolve.Resolver interface and
// can be used for logic DNS testing.
type FakeDNSResolver struct {
	sync.Mutex
	addresses map[string]string
	ports     map[string]string
}

func NewFakeDNSResolver() dnsresolve.Resolver {
	return FakeDNSResolver{
		ports:     map[string]string{},
		addresses: map[string]string{},
	}
}

// LookupSRV lookups DNS SRV record
func (f FakeDNSResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.Lock()
	defer f.Unlock()

	if v, ok := f.ports[name]; ok {
		i, err := strconv.Atoi(v)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("_%v._%v.%v", service, proto, name), []*net.SRV{{
			Port:   uint16(i),
			Target: name,
		}}, nil
	}
	return "", nil, errors.New("not found")
}

// LookupIPAddr lookups IP address by host
func (f FakeDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.Lock()
	defer f.Unlock()

	if address, ok := f.addresses[host]; ok {
		return []net.IPAddr{{
			IP: net.ParseIP(address),
		}}, nil
	}
	return nil, errors.New("not found")
}

// AddSRVEntry adds a DNS record to r using name and service as the
// key, and the host and port in u as the values. r must be a Resolver
// that was created by NewFakeDNSResolver().
func AddSRVEntry(r dnsresolve.Resolver, name, service string, u *url.URL) (err error) {
	f := r.(FakeDNSResolver)
	f.Lock()
	defer f.Unlock()

	key := fmt.Sprintf("%v.%v", service, name)
	f.addresses[key], f.ports[key], err = net.SplitHostPort(u.Host)

	return
}

// Ensure that FakeDNSResolver is a valid Resolver.
var _ dnsresolve.Resolver = (*FakeDNSResolver)(nil)
