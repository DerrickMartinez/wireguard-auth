package user

import (
  // "os/exec"
  // "io"
	"time"
	// "net/url"
	// "encoding/json"

  "github.com/derrickmartinez/wireguard-auth/pkg/util"

  "github.com/aws/aws-sdk-go/service/dynamodb"
  // "golang.zx2c4.com/wireguard/wgctrl"
  "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/spf13/viper"
  log "github.com/sirupsen/logrus"

)

func Sync(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  // wgClient := wgctrl.New()
  privateKey, err := wgtypes.GeneratePrivateKey()
  if err != nil {
    log.Errorf("Error getting key: %v", err)
  }
  log.Info(privateKey)
  for {
    log.Info("HERE")
    time.Sleep(time.Minute * time.Duration(viper.GetInt("syncInterval")))
  }

  return false
}