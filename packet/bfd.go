// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bgp

const (
	// BFD_PROTO_VERSION BFD protocl version
	BFD_PROTO_VERSION = 1
)

// RFC5881 4. Encapsulation
const (
	// BFD_CTRL_PORT control port for BFD
	BFD_CTRL_PORT = 3784
	// BFD_ECHO_PORT echo port for BFD
	BFD_ECHO_PORT = 3785
	// BFD_SRC_PORT_MIN minimum source port for a message
	BFD_SRC_PORT_MIN = 49152
	// BFD_SRC_PORT_MAX maximum source port for a message
	BFD_DST_PORT_MAX = 65535
)

// RFC5880 4.1. Generic BFD Control Packet Format
const (
	BFD_DIAG_NO_DIAGNOSTIC = iota
	BFD_DIAG_CTRL_DETECT_TIME_EXP
	BFD_DIAG_ECHO_FUNC_FAIL
	BFD_DIAG_NEIGH_SIG_SESS_DOWN
	BFD_DIAG_FWD_PLN_RST
	BFD_DIAG_PATH_DOWN
	BFD_DIAG_CONCAT_PATH_DOWN
	BFD_DIAG_ADMIN_DOWN
	BFD_DIAG_REV_CONCAT_PATH_DOWN
	// 9-31 reserved for future use
)

const (
	BFD_STA_ADMIN_DOWN = iota
	BFD_STA_DOWN
	BFD_STA_INIT
	BFD_STA_UP
)

const (
	BFD_AUTH_RESERVERD = iota
	BFD_AUTH_SIMPLE_PASS
	BFD_AUTH_KEYED_MD5
	BFD_AUTH_METI_KEYED_MD5
	BFD_AUTH_KEYED_SHA1
	BFD_AUTH_METI_KEYED_SHA1
	// 6-255 reserved for future use
)

/*

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       My Discriminator                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Your Discriminator                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Desired Min TX Interval                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Required Min RX Interval                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Required Min Echo RX Interval                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

An optional Authentication Section MAY be present:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Auth Type   |   Auth Len    |    Authentication Data...     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

// BFDMessage packet required methids
type BFDMessage interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

// BFDCtrlPkt Control packet
type BFDCtrlPkt struct {
	Version         uint8
	Diag            uint8
	State           uint8
	Poll            bool
	Final           bool
	CPInd           bool
	AuthPres        bool
	Demand          bool
	Multi           bool
	DetectMult      uint8
	MyDisc          uint32
	YourDisc        uint32
	DesMinTXInt     uint32
	ReqMinRXInt     uint32
	ReqMinEchoRXInt uint32
	AuthHeader      BFDAuthHeader
}

// BFDAuthHeader auth header interface
type BFDAuthHeader interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

// RFC5880 4.2. Simple Password Authentication Section Format
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// BFDAuthSimplePass Auth header for simple password
type BFDAuthSimplePass struct {
	AuthType  uint8
	AuthLen   uint8
	AuthKeyID uint8
	Password  []byte // 1-16 bytes
}

// RFC5880 4.3. Keyed MD5 and Meticulous Keyed MD5 Authentication Section Format
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Auth Key/Digest...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// BFDAuthKeyedMD5 auth header for keyed MD5
type BFDAuthKeyedMD5 struct {
	AuthType   uint8
	AuthLen    uint8
	AuthKeyID  uint8
	Reserved   uint8
	SeqNumber  uint32
	AuthDigest []byte // 16 byte
}

// RFC5880 4.4.  Keyed SHA1 and Meticulous Keyed SHA1 Authentication Section Format
/*

0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Auth Key/Hash...                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                              ...                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

// BFDAuthKeyedSHA1 auth header for keyed SHA1
type BFDAuthKeyedSHA1 struct {
	AuthType   uint8
	AuthLen    uint8
	AuthKeyID  uint8
	Reserved   uint8
	SeqNumber  uint32
	AuthDigest []byte // 20 byte
}

// BFDEchoPkt echo packet
type BFDEchoPkt struct {
	Data []byte
}

// ParseBFDCtrlMessage parse a control message
func ParseBFDCtrlMessage(data []byte) (*BFDMessage, error) {
	pkt := &BFDCtrlPkt{}

	pkt.AuthPres = false

	return nil, nil
}

// ParseBFDEchoMessage parse an echo message
func ParseBFDEchoMessage(data []byte) (*BFDMessage, error) {
	pkt := &BFDEchoPkt{}

	pkt.Data = data

	return nil, nil
}
