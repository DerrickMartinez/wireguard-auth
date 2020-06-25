

package mfa

import (
	"time"
	"net/url"
  "regexp"
	"encoding/json"

  "github.com/derrickmartinez/wireguard-auth/pkg/util"
  "github.com/derrickmartinez/wireguard-auth/pkg/user"

  "github.com/ZachtimusPrime/Go-Splunk-HTTP/splunk"
  "github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/duosecurity/duo_api_golang"
	"github.com/spf13/viper"
  log "github.com/sirupsen/logrus"
)

type DuoResult struct {
   Result 		string
   Status 		string
   Status_msg   string
}

type DuoResponse struct {
	Response DuoResult
	Stat     string
}

func Validate(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  // find email from pubkey
  authUser := user.GetUser(vars.PubKey, svc)
  if authUser.Email == "" {
    log.Error("Unable to locate user's email in table")
    return false
  }

  // Extract username from email address
  reg := regexp.MustCompile("(.*)@.*")
  user := reg.ReplaceAllString(authUser.Email, "${1}")

  duo := duoapi.NewDuoApi(viper.GetString("mfa.ikey"),viper.GetString("mfa.skey"),viper.GetString("mfa.host"),"wireguard-auth",duoapi.SetTimeout(20*time.Second))
  v := url.Values{}
  v.Add("username", user)
  v.Add("factor", "auto")
  v.Add("device", "auto")
  _, bytes, err := duo.SignedCall("POST", "/auth/v2/auth", v, duoapi.UseTimeout)
  if (err != nil || bytes == nil) {
    log.Error("Error")
    return false
  }
  var duoResp DuoResponse
  err = json.Unmarshal(bytes, &duoResp)
  if err != nil {
  	log.Error("Error decoding response")
  	return false
  }

    if viper.GetBool("splunk.enabled") {
      // Set up splunk client
      splunk := splunk.NewClient(
        nil,
        "https://"+viper.GetString("splunk.server")+":8088/services/collector",
        viper.GetString("splunk.token"),
        viper.GetString("splunk.source"),
        viper.GetString("splunk.sourcetype"),
        viper.GetString("splunk.index"),
      )
      var i interface{}

      m := map[string]string{"msg": "VPN auth request",  "profile": authUser.ProfileName, "email": authUser.Email, "endpoint": vars.Endpoint, "result": duoResp.Response.Result}
      i = m
      err := splunk.Log(i)
      if err != nil {
        log.Error(err)
      }
  }

  if duoResp.Response.Result != "allow" {
    log.Infof("User %v not allowed", user)
    return false
  }
  log.Infof("User %v allowed", user)
  return true
}