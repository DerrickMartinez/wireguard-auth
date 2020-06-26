package user

import (
  "net"
  "net/smtp"
  "os"
  "fmt"
  "text/tabwriter"
  "errors"
  "strings"
  "strconv"

  "github.com/derrickmartinez/wireguard-auth/pkg/util"

  "github.com/aws/aws-sdk-go/aws"
  "github.com/jordan-wright/email"
  "github.com/aws/aws-sdk-go/service/dynamodb"
  "github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
  "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/spf13/viper"
  log "github.com/sirupsen/logrus"
)

type User struct {
  Pubkey      string
  ProfileName string
  Privkey     string
  Psk         string
  Clientip    uint32
  Routesallow string
  Email       string
  Splittunnel bool
  Serial      int
}

type Rule struct {
    Route string
    Proto string
    Port  int
}

// Add a user to the DynamoDB table
func Add(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  var clientIP uint32 = 0
  users := scan(false, svc)
  if len(users) > 0 {
    clientIP = max(users) + 1
  } else {
    clientIP =  util.Ip2int(net.ParseIP(viper.GetString("ipPoolStart")))
  }

  privateKey, err := wgtypes.GeneratePrivateKey()
  if err != nil {
    log.Fatal("Error generating private key: %v", err)
  }

  psk, err := wgtypes.GenerateKey()
  if err != nil {
    log.Fatal("Error generating psk key: %v", err)
  }
 
  user := User {
    Pubkey: privateKey.PublicKey().String(),
    Clientip: clientIP,
    ProfileName: vars.ProfileName,
    Privkey: privateKey.String(),
    Psk: psk.String(),
    Routesallow: buildRoutes(vars),
    Email: vars.Email,
    Splittunnel: vars.SplitTunnel,
    Serial: 0,
  }

  if !addRecord(user, svc) {
    return false
  }

  if viper.GetBool("smtp.enabled") {
    err = sendEmail(user)
    if err != nil {
      log.Fatalf("Error sending email: %v", err)
      return false
    }
  }

  log.Info(vars.ProfileName + " succesfully added")

  return true
}

// Find a user and remove
func Remove(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  curRecord, err := getUser(vars, svc)
  if err != nil {
    log.Errorf("%v", err)
    return false
  } 

  if !deleteRecord(curRecord, svc) {
    return false
  }
  
  log.Info(vars.ProfileName + " succesfully removed")

  return true
}

// List all users
func List(svc *dynamodb.DynamoDB) {
  users := scan(false, svc)
  if len(users) == 0 {
    log.Error("There are no users in the table")
  }

  w := new(tabwriter.Writer)
  w.Init(os.Stdout, 0, 8, 0, '\t', 0)
  fmt.Fprintln(w, "Profile\tEmail\tPublic Key\tClient IP\tSplit tunnel?")

  for _, v := range users {
    fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n", v.ProfileName, v.Email, v.Pubkey, util.Int2ip(v.Clientip), v.Splittunnel)
  }
  w.Flush()
}

// Resend a user's email
func ResendEmail(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  user, err := getUser(vars, svc)
  if err != nil {
    log.Errorf("%v", err)
    return false
  } 
  err = sendEmail(user)
  if err != nil {
    log.Fatalf("Error sending email: %v", err)
    return false
  }
  return true
}

// Update a user's allowed routes
func UpdateRoutes(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool{
  user, err := getUser(vars, svc)
  if err != nil {
    log.Errorf("%v", err)
    return false
  }

  input := &dynamodb.UpdateItemInput{
    ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
        ":routes": {
            S: aws.String(strings.Replace(buildRoutes(vars), " ", "", -1)),
        },
        ":serial": {
            N: aws.String(strconv.Itoa(user.Serial + 1)),
        },
    },
    TableName: aws.String(viper.GetString("dynamoDBTable")),
    Key: map[string]*dynamodb.AttributeValue{
        "Pubkey": {
            S: aws.String(user.Pubkey),
        },
    },
    UpdateExpression: aws.String("set Routesallow = :routes, Serial = :serial"),
  }

  _, err = svc.UpdateItem(input)
  if err != nil {
      log.Error(err)
      return false
  }

  log.Info(vars.ProfileName + " succesfully updated")
  return true
}

// Get user by primary key
func GetUser(pubKey string, svc *dynamodb.DynamoDB) User {
  table := aws.String(viper.GetString("dynamoDBTable"))

  user := User{}
  result, err := svc.GetItem(&dynamodb.GetItemInput{
      TableName: table,
      Key: map[string]*dynamodb.AttributeValue{
          "Pubkey": {
              S: aws.String(pubKey),
          },
      },
  })

  if err != nil {
      log.Error("Error locating user in table")
      return user
  }

  err = dynamodbattribute.UnmarshalMap(result.Item, &user)
  if err != nil {
      log.Errorf("Failed to unmarshal Record, %v", err)
  }

  return user
}

// Get user by profile name
func getUser(vars *util.CmdVars, svc *dynamodb.DynamoDB) (User, error) {
  users := scan(false, svc)
  if len(users) == 0 {
    return User{}, errors.New("There are no users in the table")
  }

  user := findUser(users, vars.ProfileName)
  if user.Pubkey == "" {
    return User{}, errors.New("No profile found for "+vars.ProfileName)
  }
  return user, nil
}

// Find max
func max(arr []User) uint32 {
    var max uint32 = arr[0].Clientip
    for _, value := range arr {
        if max < value.Clientip {
            max = value.Clientip
        }
    }
    return max
}

// Scan DynamoDB and return a slice of structs
func scan(filter bool, svc *dynamodb.DynamoDB) []User {
  table := aws.String(viper.GetString("dynamoDBTable"))

  params := &dynamodb.ScanInput{
    TableName: table,
  }

  users := []User{}

  result, err := svc.Scan(params)
  if err != nil {
    log.Errorf("failed to make Query API call, %v", err)
  }

  err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &users)
  if err != nil {
    log.Errorf("failed to unmarshal Query result items, %v", err)
  }

  return users
}

// Add record
func addRecord(user User, svc *dynamodb.DynamoDB) bool {
  av, err := dynamodbattribute.MarshalMap(user)
  if err != nil {
    log.Fatal(err.Error())
    return false
  }

  input := &dynamodb.PutItemInput{
    Item:      av,
    TableName: aws.String(viper.GetString("dynamoDBTable")),
  }

  _, err = svc.PutItem(input)
  if err != nil {
    log.Fatal(err.Error())
    return false
  }

  return true
}

// Send config to user via email
func sendEmail(user User) error {
  routes := ""
  if user.Splittunnel {
    routes = strings.Join(viper.GetStringSlice("clientConfig.routes"), ", ")
  } else {
    routes = "0.0.0.0/0"
  }
  serverPubkey, err := wgtypes.ParseKey(viper.GetString("server.privateKey"))
  if err != nil {
    log.Error(err)
  }

  config := "[Interface]\nPrivateKey = "+user.Privkey+"\n"+
  "Address = "+util.Int2ip(user.Clientip).String()+"/32\n"+
  "DNS = "+viper.GetString("clientConfig.dns")+"\n\n"+
  "[Peer]\nPublicKey = "+serverPubkey.PublicKey().String()+"\n"+
  "PresharedKey = "+user.Psk+"\n"+
  "AllowedIPs = "+routes+"\n"+
  "Endpoint = "+viper.GetString("clientConfig.serverAddress")+"\n"+
  "PersistentKeepalive = 25\n"
  e := email.NewEmail()
  e.From = viper.GetString("smtp.from")
  e.To = []string{user.Email}
  e.Subject = "Wireguard VPN config ["+user.ProfileName+"]"
  e.Text = []byte(viper.GetString("smtp.body"))
  e.Attach(strings.NewReader(config), user.ProfileName+".conf", "application/octet-stream")

  if viper.GetBool("smtp.authLogin") {
    err := e.Send(viper.GetString("smtp.server")+":"+viper.GetString("smtp.port"), smtp.PlainAuth("", viper.GetString("smtp.username"), viper.GetString("smtp.password"), viper.GetString("smtp.server")))
    if err != nil {
      return err
    }
  } else {
    err := e.Send(viper.GetString("smtp.server")+":"+viper.GetString("smtp.port"), nil)
    if err != nil {
      return err
    }
  }
  log.Infof("Email sent to %v", user.Email)
  return nil
}

// Find a public key from the profile name
func findUser(users []User, profilename string) User {
  for _, v := range users {
    if v.ProfileName == profilename {
      return v
    }
  }
  return User{}
}

// Delete record
func deleteRecord(user User, svc *dynamodb.DynamoDB) bool {
  table := aws.String(viper.GetString("dynamoDBTable"))

  input := &dynamodb.DeleteItemInput{
    Key: map[string]*dynamodb.AttributeValue{
        "Pubkey": {
            S: aws.String(user.Pubkey),
        },
    },
    TableName: table,
  }

  _, err := svc.DeleteItem(input)
  if err != nil {
    log.Infof("Got error calling DeleteItem: %v", err)
    return false
  }
  return true
}

func buildRoutes(vars  *util.CmdVars) string {
  routes := ""
  if len(vars.Routes) > 0 {
    routes = strings.Replace(vars.Routes, " ", "", -1)
  } else {
    var rules []Rule
    err := viper.UnmarshalKey("ruleProfiles."+vars.Rule, &rules)
    if err != nil {
      log.Error(err)
      return ""
    }
    if len(rules) == 0 {
      log.Error("Unable to match the specifed rule against ruleProfiles")
      return ""
    }

    var tmpRoutes []string
    for _, r := range rules {
      if r.Port != 0 {
        tmpRoutes = append(tmpRoutes, r.Route+"->"+strconv.Itoa(r.Port)+"/"+r.Proto)
      } else {
        tmpRoutes = append(tmpRoutes, r.Route)
      }
    }
    routes = strings.Join(tmpRoutes, ",")
  }
  return routes
}