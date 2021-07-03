package hepparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/VictoriaMetrics/fastcache"
	"github.com/cespare/xxhash"
	"github.com/negbie/sipparser"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var Setting HeplifyServer

type HeplifyServer struct {
	HEPAddr            string   `default:"0.0.0.0:9060"`
	HEPTCPAddr         string   `default:""`
	HEPTLSAddr         string   `default:"0.0.0.0:9060"`
	ESAddr             string   `default:""`
	ESDiscovery        bool     `default:"true"`
	ESUser             string   `default:""`
	ESPass             string   `default:""`
	LokiURL            string   `default:""`
	LokiBulk           int      `default:"400"`
	LokiTimer          int      `default:"4"`
	LokiBuffer         int      `default:"100000"`
	LokiHEPFilter      []int    `default:"1,5,100"`
	ForceHEPPayload    []int    `default:""`
	PromAddr           string   `default:":9096"`
	PromTargetIP       string   `default:""`
	PromTargetName     string   `default:""`
	DBShema            string   `default:"homer5"`
	DBDriver           string   `default:"mysql"`
	DBAddr             string   `default:"localhost:3306"`
	DBUser             string   `default:"root"`
	DBPass             string   `default:""`
	DBDataTable        string   `default:"homer_data"`
	DBConfTable        string   `default:"homer_configuration"`
	DBBulk             int      `default:"400"`
	DBTimer            int      `default:"4"`
	DBBuffer           int      `default:"400000"`
	DBWorker           int      `default:"8"`
	DBRotate           bool     `default:"true"`
	DBPartLog          string   `default:"2h"`
	DBPartIsup         string   `default:"6h"`
	DBPartSip          string   `default:"2h"`
	DBPartQos          string   `default:"6h"`
	DBDropDays         int      `default:"14"`
	DBDropDaysCall     int      `default:"0"`
	DBDropDaysRegister int      `default:"0"`
	DBDropDaysDefault  int      `default:"0"`
	DBDropOnStart      bool     `default:"false"`
	Dedup              bool     `default:"false"`
	DiscardMethod      []string `default:""`
	AlegIDs            []string `default:""`
	CustomHeader       []string `default:""`
	SIPHeader          []string `default:"ruri_user,ruri_domain,from_user,from_domain,to_user,callid,method,user_agent"`
	LogDbg             string   `default:""`
	LogLvl             string   `default:"info"`
	LogStd             bool     `default:"false"`
	LogSys             bool     `default:"false"`
	Config             string   `default:"./heplify-server.toml"`
	ConfigHTTPAddr     string   `default:""`
	ConfigHTTPPW       string   `default:""`
}

// HEP chunks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
	NodeName  = 19 // Chunk 0x0013 NodeName
)

var (
	ErrInvalidLengthHep = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowHep   = fmt.Errorf("proto: integer overflow")
	dedup               = fastcache.New(32 * 1024 * 1024)
	strQuote            = []byte("\"")
	strEscQuote         = []byte("\\\"")
	noVal               = []byte("")
)

// HEP represents HEP packet
type HEP struct {
	Version     uint32 `protobuf:"varint,1,req,name=Version" json:"Version"`
	Protocol    uint32 `protobuf:"varint,2,req,name=Protocol" json:"Protocol"`
	SrcIP       string `protobuf:"bytes,3,req,name=SrcIP" json:"SrcIP"`
	DstIP       string `protobuf:"bytes,4,req,name=DstIP" json:"DstIP"`
	SrcPort     uint32 `protobuf:"varint,5,req,name=SrcPort" json:"SrcPort"`
	DstPort     uint32 `protobuf:"varint,6,req,name=DstPort" json:"DstPort"`
	Tsec        uint32 `protobuf:"varint,7,req,name=Tsec" json:"Tsec"`
	Tmsec       uint32 `protobuf:"varint,8,req,name=Tmsec" json:"Tmsec"`
	ProtoType   uint32 `protobuf:"varint,9,req,name=ProtoType" json:"ProtoType"`
	NodeID      uint32 `protobuf:"varint,10,req,name=NodeID" json:"NodeID"`
	NodePW      string `protobuf:"bytes,11,req,name=NodePW" json:"NodePW"`
	Payload     string `protobuf:"bytes,12,req,name=Payload" json:"Payload"`
	CID         string `protobuf:"bytes,13,req,name=CID" json:"CID"`
	Vlan        uint32 `protobuf:"varint,14,req,name=Vlan" json:"Vlan"`
	ProtoString string
	Timestamp   time.Time
	SIP         *sipparser.SipMsg
	NodeName    string
	SID         string
}

// DecodeHEP returns a parsed HEP message
func DecodeHEP(packet []byte) (*HEP, error) {
	hep := &HEP{}
	err := hep.parse(packet)
	if err != nil {
		return nil, err
	}
	return hep, nil
}

func (h *HEP) parse(packet []byte) error {
	var err error
	if bytes.HasPrefix(packet, []byte{0x48, 0x45, 0x50, 0x33}) {
		err = h.parseHEP(packet)
		if err != nil {
			log.Println(err)
			return err
		}
	} else {
		err = h.Unmarshal(packet)
		if err != nil {
			log.Printf("malformed packet with length %d which is neither hep nor protobuf encapsulated", len(packet))
			return err
		}
	}

	t := time.Now()
	h.normPayload(t)
	if h.ProtoType == 0 {
		return nil
	}

	h.Timestamp = time.Unix(int64(h.Tsec), int64(h.Tmsec*1000))
	d := t.Sub(h.Timestamp)
	if d < 0 || (h.Tsec == 0 && h.Tmsec == 0) {
		log.Printf("hep got timestamp in the future with delta: %d from nodeID %d", d, h.NodeID)
		h.Timestamp = t
	}

	if h.ProtoType == 1 && len(h.Payload) > 32 {
		err = h.parseSIP()
		if err != nil {
			log.Printf("%v\n%q\nnodeID: %d, protoType: %d, version: %d, protocol: %d, length: %d, flow: %s:%d->%s:%d\n\n",
				err, h.Payload, h.NodeID, h.ProtoType, h.Version, h.Protocol, len(h.Payload), h.SrcIP, h.SrcPort, h.DstIP, h.DstPort)
			return err
		}

		if len(Setting.DiscardMethod) > 0 {
			for k := range Setting.DiscardMethod {
				if Setting.DiscardMethod[k] == h.SIP.CseqMethod {
					h.ProtoType = 0
					return nil
				}
			}
		}
	}

	if h.NodeName == "" {
		h.NodeName = strconv.FormatUint(uint64(h.NodeID), 10)
	}

	//log.Printf("hep %+v\n\n", h)
	return nil
}

var fixUTF8 = func(r rune) rune {
	if r == utf8.RuneError || r == '\x00' {
		return -1
	}
	return r
}

func (h *HEP) normPayload(t time.Time) {
	if Setting.Dedup {
		ts := uint64(t.UnixNano())
		kh := make([]byte, 8)
		ks := xxhash.Sum64String(h.Payload)
		binary.BigEndian.PutUint64(kh, ks)

		if buf := dedup.Get(nil, kh); buf != nil {
			i := binary.BigEndian.Uint64(buf)
			d := ts - i
			if d < 400e6 || d > 1e18 {
				h.ProtoType = 0
				return
			}
		}

		tb := make([]byte, 8)
		binary.BigEndian.PutUint64(tb, ts)
		dedup.Set(kh, tb)
	}
	if !utf8.ValidString(h.Payload) {
		h.Payload = strings.Map(fixUTF8, h.Payload)
	} else if Setting.DBDriver == "postgres" && strings.Index(h.Payload, "\x00") > -1 {
		h.Payload = strings.Map(fixUTF8, h.Payload)
	}
}

func (h *HEP) EscapeFields(w io.Writer, tag string) (int, error) {
	escape := func(s string) (b []byte) {
		if len(s) > 0 && strings.ContainsRune(s, '"') {
			return bytes.Replace([]byte(s), strQuote, strEscQuote, -1)
		}
		return []byte(s)
	}

	switch tag {
	case "callid":
		return w.Write(escape(h.SIP.CallID))
	case "method":
		return w.Write(escape(h.SIP.FirstMethod))
	case "ruri_user":
		return w.Write(escape(h.SIP.URIUser))
	case "ruri_domain":
		return w.Write(escape(h.SIP.URIHost))
	case "from_user":
		return w.Write(escape(h.SIP.FromUser))
	case "from_domain":
		return w.Write(escape(h.SIP.FromHost))
	case "from_tag":
		return w.Write(escape(h.SIP.FromTag))
	case "to_user":
		return w.Write(escape(h.SIP.ToUser))
	case "to_domain":
		return w.Write(escape(h.SIP.ToHost))
	case "to_tag":
		return w.Write(escape(h.SIP.ToTag))
	case "via":
		return w.Write(escape(h.SIP.ViaOne))
	case "contact_user":
		return w.Write(escape(h.SIP.ContactUser))
	case "contact_domain":
		return w.Write(escape(h.SIP.ContactHost))
	case "user_agent":
		return w.Write(escape(h.SIP.UserAgent))
	case "pid_user":
		return w.Write(escape(h.SIP.PaiUser))
	case "auth_user":
		return w.Write(escape(h.SIP.AuthUser))
	case "server":
		return w.Write(escape(h.SIP.Server))
	case "content_type":
		return w.Write(escape(h.SIP.ContentType))
	case "reason":
		return w.Write(escape(h.SIP.ReasonVal))
	case "diversion":
		return w.Write(escape(h.SIP.DiversionVal))
	default:
		return w.Write(noVal)
	}
}

func (h *HEP) parseHEP(packet []byte) error {
	length := binary.BigEndian.Uint16(packet[4:6])
	if int(length) != len(packet) {
		return fmt.Errorf("HEP packet length is %d but should be %d", len(packet), length)
	}
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := packet[currentByte:]
		if len(hepChunk) < 6 {
			return fmt.Errorf("HEP chunk must be >= 6 byte long but is %d", len(hepChunk))
		}
		//chunkVendorId := binary.BigEndian.Uint16(hepChunk[:2])
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])
		if len(hepChunk) < int(chunkLength) || int(chunkLength) < 6 {
			return fmt.Errorf("HEP chunk with %d byte < chunkLength %d or chunkLength < 6", len(hepChunk), chunkLength)
		}
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case Version, Protocol, ProtoType:
			if len(chunkBody) != 1 {
				return fmt.Errorf("HEP chunkType %d should be 1 byte long but is %d", chunkType, len(chunkBody))
			}
		case SrcPort, DstPort, Vlan:
			if len(chunkBody) != 2 {
				return fmt.Errorf("HEP chunkType %d should be 2 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP4SrcIP, IP4DstIP, Tsec, Tmsec, NodeID:
			if len(chunkBody) != 4 {
				return fmt.Errorf("HEP chunkType %d should be 4 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP6SrcIP, IP6DstIP:
			if len(chunkBody) != 16 {
				return fmt.Errorf("HEP chunkType %d should be 16 byte long but is %d", chunkType, len(chunkBody))
			}
		}

		switch chunkType {
		case Version:
			h.Version = uint32(chunkBody[0])
		case Protocol:
			h.Protocol = uint32(chunkBody[0])
		case IP4SrcIP:
			h.SrcIP = net.IP(chunkBody).To4().String()
		case IP4DstIP:
			h.DstIP = net.IP(chunkBody).To4().String()
		case IP6SrcIP:
			h.SrcIP = net.IP(chunkBody).To16().String()
		case IP6DstIP:
			h.DstIP = net.IP(chunkBody).To16().String()
		case SrcPort:
			h.SrcPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case DstPort:
			h.DstPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case Tsec:
			h.Tsec = binary.BigEndian.Uint32(chunkBody)
		case Tmsec:
			h.Tmsec = binary.BigEndian.Uint32(chunkBody)
		case ProtoType:
			h.ProtoType = uint32(chunkBody[0])
			switch h.ProtoType {
			case 1:
				h.ProtoString = "sip"
			case 5:
				h.ProtoString = "rtcp"
			case 34:
				h.ProtoString = "rtpagent"
			case 35:
				h.ProtoString = "rtcpxr"
			case 38:
				h.ProtoString = "horaclifix"
			case 53:
				h.ProtoString = "dns"
			case 100:
				h.ProtoString = "log"
			default:
				h.ProtoString = strconv.Itoa(int(h.ProtoType))
			}
		case NodeID:
			h.NodeID = binary.BigEndian.Uint32(chunkBody)
		case NodePW:
			h.NodePW = string(chunkBody)
		case Payload:
			h.Payload = string(chunkBody)
		case CID:
			h.CID = string(chunkBody)
		case Vlan:
			h.Vlan = uint32(binary.BigEndian.Uint16(chunkBody))
		case NodeName:
			h.NodeName = string(chunkBody)
		default:
		}
		currentByte += chunkLength
	}
	return nil
}

func (m *HEP) Unmarshal(dAtA []byte) error {
	var hasFields [1]uint64
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowHep
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: HEP: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HEP: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			m.Version = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Version |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000001)
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Protocol", wireType)
			}
			m.Protocol = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Protocol |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000002)
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SrcIP", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthHep
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SrcIP = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00000004)
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DstIP", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthHep
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DstIP = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00000008)
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field SrcPort", wireType)
			}
			m.SrcPort = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.SrcPort |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000010)
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field DstPort", wireType)
			}
			m.DstPort = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.DstPort |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000020)
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Tsec", wireType)
			}
			m.Tsec = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Tsec |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000040)
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Tmsec", wireType)
			}
			m.Tmsec = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Tmsec |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000080)
		case 9:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ProtoType", wireType)
			}
			m.ProtoType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ProtoType |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000100)
		case 10:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodeID", wireType)
			}
			m.NodeID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NodeID |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000200)
		case 11:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodePW", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthHep
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NodePW = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00000400)
		case 12:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Payload", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthHep
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Payload = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00000800)
		case 13:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthHep
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00001000)
		case 14:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Vlan", wireType)
			}
			m.Vlan = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHep
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Vlan |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00002000)
		default:
			iNdEx = preIndex
			skippy, err := skipHep(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthHep
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (h *HEP) parseSIP() error {
	h.SIP = sipparser.ParseMsg(h.Payload, Setting.AlegIDs...)
	if h.SIP.Error != nil {
		return h.SIP.Error
	} else if len(h.SIP.CseqMethod) < 3 {
		return errors.New("could not find a valid CSeq in packet")
	} else if len(h.SIP.CallID) < 1 {
		return errors.New("could not find a valid Call-ID in packet")
	}
	if h.SIP.FirstMethod == "" {
		h.SIP.FirstMethod = h.SIP.FirstResp
	}

	if h.CID == "" {
		if h.SIP.XCallID != "" {
			h.CID = h.SIP.XCallID
		} else {
			h.CID = h.SIP.CallID
		}
	}

	h.SID = h.SIP.CallID

	return nil
}

func skipHep(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowHep
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowHep
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowHep
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthHep
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowHep
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipHep(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}
