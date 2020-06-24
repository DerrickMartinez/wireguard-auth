package user

import (
  "net"
  "net/smtp"
  "os"
  "fmt"
  "text/tabwriter"
  "strings"

  "github.com/derrickmartinez/wireguard-auth/pkg/util"

  "github.com/aws/aws-sdk-go/aws"
  "github.com/jordan-wright/email"
  "github.com/aws/aws-sdk-go/service/dynamodb"
  "github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
  "github.com/aws/aws-sdk-go/service/dynamodb/expression"
  "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/spf13/viper"
  "github.com/segmentio/ksuid"
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
  Active      bool
  Splittunnel bool
  Serial      int
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

  routesAllow := strings.Join(viper.GetStringSlice("defaultRoutesAllow"), ", ")

  privateKey, err := wgtypes.GeneratePrivateKey()
  if err != nil {
    log.Fatal("Error generating private key: %v", err)
  }

  psk, err := wgtypes.GenerateKey()
  if err != nil {
    log.Fatal("Error generating psk key: %v", err)
  }
 
  user := User {
    Pubkey: ksuid.New().String(),
    Clientip: clientIP,
    ProfileName: vars.ProfileName,
    Privkey: privateKey.String(),
    Psk: psk.String(),
    Routesallow: routesAllow,
    Email: vars.Email,
    Active: false,
    Splittunnel: vars.SplitTunnel,
    Serial: 1,
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
    log.Infof("Email sent to %v", user.Email)
  }

  log.Info(vars.ProfileName + " succesfully added")

  return true
}

// Find a user and remove
func Remove(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  users := scan(false, svc)
  if len(users) == 0 {
    log.Error("There are no users in the table")
    return false
  }

  curRecord := findUser(users, vars.ProfileName)
  if curRecord.Pubkey == "" {
    log.Error("No user found to remove")
    return false
  }

  if !deleteRecord(curRecord, svc) {
    return false
  }
  
  log.Info(vars.ProfileName + " succesfully removed")

  return true
}

// Find an exisiting profile name and set the public key
func Rotate(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
  users := scan(false, svc)
  if len(users) == 0 {
    log.Error("There are no users in the table")
    return false
  }

  oldRecord := findUser(users, vars.ProfileName)
  if oldRecord.Pubkey == "" {
    log.Error("No user found to rotate")
    return false
  }

  newRecord := oldRecord
  newRecord.Pubkey = vars.PubKey

  // Ensure active is set to true
  newRecord.Active = true

  if !addRecord(newRecord, svc) {
    return false
  }

  // Clean up old record

  if !deleteRecord(oldRecord, svc) {
    return false
  }

  log.Info(vars.ProfileName + " succesfully rotated")

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

// Generate params for query
func dynamoParams(filter bool) *dynamodb.ScanInput {
  table := aws.String(viper.GetString("dynamoDBTable"))

  if filter {
    filt := expression.Name("Active").Equal(expression.Value(true))
    expr, err := expression.NewBuilder().WithFilter(filt).Build()
    if err != nil {
      log.Fatal("Error building expression")
    }

    // Build the query input parameters
    params := &dynamodb.ScanInput{
      TableName: table,
      FilterExpression: expr.Filter(),
      ExpressionAttributeNames:  expr.Names(),
      ExpressionAttributeValues: expr.Values(),
    }
    return params
  } else {
    // all items
    params := &dynamodb.ScanInput{
      TableName: table,
    }
    return params
  }
}

// Scan DynamoDB and return a slice of structs
func scan(filter bool, svc *dynamodb.DynamoDB) []User {
  params := dynamoParams(filter)
  result, err := svc.Scan(params)
  if err != nil {
    log.Errorf("failed to make Query API call, %v", err)
  }

  users := []User{}

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

  config := "[Interface]\nPrivateKey = "+user.Privkey+"\n"+
  "Address = "+util.Int2ip(user.Clientip).String()+"/32\n"+
  "DNS = "+viper.GetString("clientConfig.dns")+"\n\n"+
  "[Peer]\nPublicKey = "+viper.GetString("clientConfig.serverPubkey")+"\n"+
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