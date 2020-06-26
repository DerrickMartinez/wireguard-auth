package util

import (
	"encoding/binary"
	"net"
)

type CmdVars struct {
    PubKey    	string
    ProfileName string
    SplitTunnel bool
    Routes      string
    Rule        string
    Endpoint    string
    Email	    string
}


func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func NextIP(ip net.IP, inc uint) net.IP {
    i := ip.To4()
    v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
    v += inc
    v3 := byte(v & 0xFF)
    v2 := byte((v >> 8) & 0xFF)
    v1 := byte((v >> 16) & 0xFF)
    v0 := byte((v >> 24) & 0xFF)
    return net.IPv4(v0, v1, v2, v3)
}
