package user

import (
  "strings"
	"time"
  "net"

  "github.com/derrickmartinez/wireguard-auth/pkg/util"

  "github.com/aws/aws-sdk-go/service/dynamodb"
  "github.com/coreos/go-iptables/iptables"
  "golang.zx2c4.com/wireguard/wgctrl"
  "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/spf13/viper"
  log "github.com/sirupsen/logrus"

)

func Sync(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  wgClient, err := wgctrl.New()
  if err != nil {
    log.Errorf("Error creating client: %v", err)
    return false
  }

  ipt, err := iptables.New()
  if err != nil {
    log.Errorf("IP Tables error: %v", err)
    return false
  }

  wgDevice := viper.GetString("server.wgInterface")
  prevUsers := []User{}
  curUsers := []User{}

  for {
    curUsers = scan(false, svc)
    curUsersMap := usersMap(curUsers)
    prevUsersMap := usersMap(prevUsers)
    peerConfig := []wgtypes.PeerConfig{}

    d, err := wgClient.Device(wgDevice)
    if err != nil {
      log.Errorf("Error getting wireguard device: %v", err)
      return false
    }

    // Check to see if any peers need removing
    for _,v := range d.Peers {
      if curUsersMap[v.PublicKey.String()].Privkey == "" {
        config := removePeer(v, ipt)
        peerConfig = Append(peerConfig, config)
      }
    }

    peersMap := peersMap(d.Peers)
    for _,v := range curUsers {
      // Add missing peer
      if !peersMap[v.Pubkey] {
        config := addPeer(v, ipt)
        peerConfig = Append(peerConfig, config)
      }
      // Update routes if changed
      if v.Serial > prevUsersMap[v.Pubkey].Serial {
        updateRoutes(v, ipt)
      }
    }

    // Process changes
    if len(peerConfig) > 0 {
      key, err := wgtypes.ParseKey(viper.GetString("server.privateKey"))
      if err != nil {
        log.Error(err)
      }
      port := viper.GetInt("server.port")
      config := wgtypes.Config{
        PrivateKey: &key,
        ListenPort: &port,
        ReplacePeers: false,
        Peers: peerConfig,
      }
      err = wgClient.ConfigureDevice(wgDevice, config) 
      if err != nil {
        log.Errorf("Error configuring wireguard device: %v", err)
      }
    }

    prevUsers = curUsers
    time.Sleep(time.Second * time.Duration(viper.GetInt("syncInterval")))
  }

  return false
}

func Extend(slice []wgtypes.PeerConfig, element wgtypes.PeerConfig) []wgtypes.PeerConfig {
    n := len(slice)
    if n == cap(slice) {
        newSlice := make([]wgtypes.PeerConfig, len(slice), 2*len(slice)+1)
        copy(newSlice, slice)
        slice = newSlice
    }
    slice = slice[0 : n+1]
    slice[n] = element
    return slice
}

func Append(slice []wgtypes.PeerConfig, items ...wgtypes.PeerConfig) []wgtypes.PeerConfig {
    for _, item := range items {
        slice = Extend(slice, item)
    }
    return slice
}

func usersMap(users []User) map[string]User{
  usersMap := map[string]User {}
  for _, v := range users {
    usersMap[v.Pubkey] = v
  }
  return usersMap
}

func peersMap(peers []wgtypes.Peer) map[string]bool{
  localMap := map[string]bool {}
  for _, v := range peers {
    localMap[v.PublicKey.String()] = true
  }
  return localMap
}

func removePeer(peer wgtypes.Peer, ipt *iptables.IPTables) wgtypes.PeerConfig {
  log.Infof("Remove %v from local", peer.PublicKey)
  peerIP := peer.AllowedIPs[0].String()
  removeIP, _, err := net.ParseCIDR(peerIP)
  if err != nil {
    log.Error(err)
  }

  clearIPTables(removeIP.String(), ipt)

  peerConfig := wgtypes.PeerConfig{
    PublicKey: peer.PublicKey,
    Remove: true,
  }

  return peerConfig
}

func addPeer(peer User, ipt *iptables.IPTables) wgtypes.PeerConfig {
  log.Infof("Add %v to local", peer.Pubkey)
  // Clear in case it already exists from a previous process
  clearIPTables(util.Int2ip(peer.Clientip).String(), ipt)
  addIPTables(peer, ipt)

  psk, err := wgtypes.ParseKey(peer.Psk)
  if err != nil {
    log.Error(err)
  }

  clientip := []net.IPNet{
    net.IPNet{
      IP: util.Int2ip(peer.Clientip),
      Mask: net.IPv4Mask(255, 255, 255, 255),
    },
  }

  pubkey, err := wgtypes.ParseKey(peer.Pubkey)
  if err != nil {
    log.Error(err)
  }

  peerConfig := wgtypes.PeerConfig{
    PublicKey: pubkey,
    PresharedKey: &psk,
    AllowedIPs: clientip,
  }

  return peerConfig
}

func updateRoutes(peer User, ipt *iptables.IPTables) {
  log.Infof("Update routes for %v", peer.Pubkey)
  clearIPTables(util.Int2ip(peer.Clientip).String(), ipt)
  addIPTables(peer, ipt)
}

func addIPTables(user User, ipt *iptables.IPTables) bool {
  extInterface := viper.GetString("server.extInterface")
  ip := util.Int2ip(user.Clientip).String()
  err := ipt.NewChain("filter",ip)
  if err != nil {
    log.Error(err)
    return false
  }
  routes := strings.Split(user.Routesallow, ",")
  for _, v := range routes {
    v := strings.Split(v, "->")
    destIP := v[0]
    if len(v) > 1 {
      v := strings.Split(v[1], "/")
      err = ipt.Append("filter", ip, "-s", ip+"/32", "-p", v[1], "--dport", v[0], "-d", destIP, "-o", extInterface, "-j", "ACCEPT")
      if err != nil {
        log.Error(err)
        return false
      }
    } else {
      err = ipt.Append("filter", ip, "-s", ip+"/32", "-d", destIP, "-o", extInterface, "-j", "ACCEPT")
      if err != nil {
        log.Error(err)
        return false
      }
    }
  }
  if !user.Splittunnel && viper.GetBool("allowInternet") {
    err = ipt.Append("filter", ip, "-s", ip+"/32", "-d", "10.0.0.0/8", "-o", extInterface, "-j", "DROP")
    if err != nil {
      log.Error(err)
      return false
    }
    err = ipt.Append("filter", ip, "-s", ip+"/32", "-d", "172.16.0.0/12", "-o", extInterface, "-j", "DROP")
    if err != nil {
      log.Error(err)
      return false
    }
    err = ipt.Append("filter", ip, "-s", ip+"/32", "-d", "192.168.0.0/16", "-o", extInterface, "-j", "DROP")
    if err != nil {
      log.Error(err)
      return false
    }
    err = ipt.Append("filter", ip, "-s", ip+"/32", "-d", "0.0.0.0/0", "-o", extInterface, "-j", "ACCEPT")
    if err != nil {
      log.Error(err)
      return false
    }
  }
  err = ipt.Insert("filter", "FORWARD", 1, "-j", ip)
  if err != nil {
    log.Error(err)
    return false
  }
  return true
}

func clearIPTables(ip string, ipt *iptables.IPTables) bool {
  // Check to see if the chain exists
  tables, err := ipt.ListChains("filter")
  if !findChain(tables, ip) {
    return false
  }
  err = ipt.ClearChain("filter", ip)
  if err != nil {
    log.Error(err)
    return false
  }
  err = ipt.Delete("filter", "FORWARD", "-j", ip)
  if err != nil {
    log.Error(err)
  }
  err = ipt.DeleteChain("filter", ip)
  if err != nil {
    log.Error(err)
    return false
  }
  return true
}

func findChain(slice []string, val string) bool {
    for _, item := range slice {
        if item == val {
            return true
        }
    }
    return false
}