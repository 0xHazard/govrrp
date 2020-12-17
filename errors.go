// Copyright 2020 govrrp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package govrrp

import "errors"

var (
	errIsNil              = errors.New("input is `nil`")
	errNilHeader          = errors.New("VRRP header can't be empty")
	errNilPseudoHdr       = errors.New("pseudo-header is empty")
	errShortHeader        = errors.New("VRRP header is too short")
	errBadChecksum        = errors.New("bad VRRP checksum")
	errIfNoIPv4           = errors.New("IPv4 is supported only")
	errInvalidIPv4Addr    = errors.New("invalid IPv4 address")
	errIfNoIPv4addr       = errors.New("no IPv4 address assigned to the interface")
	errIfNotFound         = errors.New("no suitable network interface found")
	errInvalidVRRPversion = errors.New("invalid VRRP version")
	errBadIPttl           = errors.New("bad IPv4 TTL")
)
