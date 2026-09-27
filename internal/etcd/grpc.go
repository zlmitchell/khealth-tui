package etcd

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// k3s's embedded etcd serves only gRPC on 2379: no JSON gateway (it
// answers 415), no etcdctl on the host and no etcd pod to exec into. The
// probe then speaks gRPC through curl (HTTP/2 over TLS, an empty request
// frame) and prints the reply base64-encoded; these decode the three
// replies it asks for from the protobuf wire format, which needs no etcd
// client library: MemberListResponse, StatusResponse, AlarmResponse
// (etcdserverpb, api/etcdserverpb/rpc.proto).

// grpcMessage strips the gRPC frame: 1 byte compressed flag, 4 bytes length.
func grpcMessage(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, errors.New("no gRPC reply (the endpoint answered nothing, or curl lacks HTTP/2)")
	}
	if raw[0] != 0 {
		return nil, errors.New("compressed gRPC reply")
	}
	n := binary.BigEndian.Uint32(raw[1:5])
	if int(n) > len(raw)-5 {
		return nil, fmt.Errorf("truncated gRPC reply (%d of %d bytes)", len(raw)-5, n)
	}
	return raw[5 : 5+n], nil
}

// field is one protobuf field: varint value or length-delimited bytes.
type field struct {
	num  int
	v    uint64
	data []byte
}

// fields splits a protobuf message into its top-level fields.
func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return out, errors.New("bad protobuf key")
		}
		b = b[n:]
		f := field{num: int(key >> 3)}
		switch key & 7 {
		case 0: // varint
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return out, errors.New("bad varint")
			}
			f.v, b = v, b[n:]
		case 1: // fixed64
			if len(b) < 8 {
				return out, errors.New("short fixed64")
			}
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || int(l) > len(b)-n {
				return out, errors.New("bad length")
			}
			f.data, b = b[n:n+int(l)], b[n+int(l):]
		case 5: // fixed32
			if len(b) < 4 {
				return out, errors.New("short fixed32")
			}
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return out, fmt.Errorf("unsupported wire type %d", key&7)
		}
		out = append(out, f)
	}
	return out, nil
}

// grpcMembers decodes MemberListResponse{header=1, members=2}, Member{ID=1,
// name=2, peerURLs=3, clientURLs=4, isLearner=5}.
func grpcMembers(b64 string) ([]Member, error) {
	msg, err := grpcMessage(b64)
	if err != nil {
		return nil, err
	}
	top, err := fields(msg)
	if err != nil {
		return nil, err
	}
	var out []Member
	for _, f := range top {
		if f.num != 2 {
			continue
		}
		mf, err := fields(f.data)
		if err != nil {
			return out, err
		}
		var m Member
		for _, g := range mf {
			switch g.num {
			case 1:
				m.ID = fmt.Sprintf("%x", g.v)
			case 2:
				m.Name = string(g.data)
			case 3:
				m.PeerURLs = append(m.PeerURLs, string(g.data))
			case 4:
				m.ClientURLs = append(m.ClientURLs, string(g.data))
			case 5:
				m.IsLearner = g.v != 0
			}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// grpcStatus decodes StatusResponse{header=1, version=2, dbSize=3,
// leader=4, raftIndex=5, raftTerm=6, raftAppliedIndex=7, errors=8,
// dbSizeInUse=9, isLearner=10}, ResponseHeader{cluster_id=1, member_id=2}.
func grpcStatus(b64 string) (EndpointStatus, error) {
	var es EndpointStatus
	msg, err := grpcMessage(b64)
	if err != nil {
		return es, err
	}
	top, err := fields(msg)
	if err != nil {
		return es, err
	}
	for _, f := range top {
		switch f.num {
		case 1:
			hf, _ := fields(f.data)
			for _, h := range hf {
				if h.num == 2 {
					es.MemberID = fmt.Sprintf("%x", h.v)
				}
			}
		case 2:
			es.Version = string(f.data)
		case 3:
			es.DBSize = int64(f.v)
		case 4:
			es.Leader = fmt.Sprintf("%x", f.v)
		case 5:
			es.RaftIndex = f.v
		case 6:
			es.RaftTerm = f.v
		case 8:
			es.Errors = append(es.Errors, string(f.data))
		case 9:
			es.DBSizeInUse = int64(f.v)
		case 10:
			es.IsLearner = f.v != 0
		}
	}
	if es.Version == "" && es.RaftTerm == 0 {
		return es, errors.New("empty status reply")
	}
	return es, nil
}

// grpcAlarms decodes AlarmResponse{header=1, alarms=2},
// AlarmMember{memberID=1, alarm=2 (1 NOSPACE, 2 CORRUPT)}.
func grpcAlarms(b64 string) ([]Alarm, error) {
	msg, err := grpcMessage(b64)
	if err != nil {
		return nil, err
	}
	top, err := fields(msg)
	if err != nil {
		return nil, err
	}
	var out []Alarm
	for _, f := range top {
		if f.num != 2 {
			continue
		}
		af, _ := fields(f.data)
		var a Alarm
		for _, g := range af {
			switch g.num {
			case 1:
				a.MemberID = fmt.Sprintf("%x", g.v)
			case 2:
				switch g.v {
				case 1:
					a.Type = "NOSPACE"
				case 2:
					a.Type = "CORRUPT"
				default:
					a.Type = fmt.Sprint(g.v)
				}
			}
		}
		if a.Type != "" && a.Type != "0" {
			out = append(out, a)
		}
	}
	return out, nil
}
