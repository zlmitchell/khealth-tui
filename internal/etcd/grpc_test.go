package etcd

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// protobuf builders for the test
func pbVarint(num int, v uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(num)<<3)
	return binary.AppendUvarint(b, v)
}

func pbBytes(num int, data []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(num)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}

func frame(msg []byte) string {
	b := []byte{0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return base64.StdEncoding.EncodeToString(append(b, msg...))
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The replies k3s's embedded etcd gives over gRPC (no JSON gateway there),
// as the probe prints them: base64 of the gRPC frame.
func TestGRPCReplies(t *testing.T) {
	header := pbBytes(1, cat(pbVarint(1, 0xabc), pbVarint(2, 0x68ab2be31294b35d)))
	member := cat(pbVarint(1, 0x68ab2be31294b35d), pbBytes(2, []byte("lab-node-1a2b")), pbBytes(3, []byte("https://10.0.0.5:2380")), pbBytes(4, []byte("https://10.0.0.5:2379")))
	ms, err := grpcMembers(frame(cat(header, pbBytes(2, member))))
	if err != nil || len(ms) != 1 || ms[0].ID != "68ab2be31294b35d" || ms[0].Name != "lab-node-1a2b" || ms[0].ClientURLs[0] != "https://10.0.0.5:2379" {
		t.Fatalf("members %+v, %v", ms, err)
	}
	st, err := grpcStatus(frame(cat(header, pbBytes(2, []byte("3.5.21")), pbVarint(3, 4<<20), pbVarint(4, 0x68ab2be31294b35d), pbVarint(5, 900), pbVarint(6, 2), pbVarint(9, 3<<20))))
	if err != nil || st.Version != "3.5.21" || st.DBSize != 4<<20 || st.DBSizeInUse != 3<<20 || st.RaftTerm != 2 || st.Leader != "68ab2be31294b35d" || st.MemberID != "68ab2be31294b35d" {
		t.Fatalf("status %+v, %v", st, err)
	}
	al, err := grpcAlarms(frame(cat(header, pbBytes(2, cat(pbVarint(1, 0x68ab2be31294b35d), pbVarint(2, 1))))))
	if err != nil || len(al) != 1 || al[0].Type != "NOSPACE" {
		t.Fatalf("alarms %+v, %v", al, err)
	}
	if _, err := grpcMembers(""); err == nil {
		t.Error("an empty reply decoded")
	}
	// the probe output as a whole
	p := Parse("lab-node", "===ETCDCTL\nvia=grpc-gateway\n---GRPCMEMBERS\n"+frame(cat(header, pbBytes(2, member)))+"\n---GRPCSTATUS\n"+frame(cat(header, pbBytes(2, []byte("3.5.21")), pbVarint(6, 2)))+"\n---GRPCALARMS\n"+frame(header)+"\n===END\n")
	if len(p.Members) != 1 || len(p.Statuses) != 1 || p.EtcdctlVia != "grpc" {
		t.Errorf("parsed probe: members %d statuses %d via %q", len(p.Members), len(p.Statuses), p.EtcdctlVia)
	}
}
