package mfa

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/derrickmartinez/wireguard-auth/pkg/okta"
	"github.com/derrickmartinez/wireguard-auth/pkg/promtail"
	"github.com/derrickmartinez/wireguard-auth/pkg/user"
	"github.com/derrickmartinez/wireguard-auth/pkg/util"

	splunk "github.com/ZachtimusPrime/Go-Splunk-HTTP/splunk/v2"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/oschwald/geoip2-golang"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func Validate(vars *util.CmdVars, svc *dynamodb.DynamoDB) bool {
	// find email from pubkey
	authUser := user.GetUser(vars.PubKey, svc)
	if authUser.Email == "" {
		log.Error().Msg("Unable to locate user's email in table")
		return false
	}
	userIdString := okta.GetUserId(authUser.Email)
	userFactorId := okta.GetUserPushFactorId(userIdString)
	userVerfiyURL := viper.GetString("okta.orgUrl") + "/api/v1/users/" + userIdString + "/factors/" + userFactorId + "/verify"
	verificationStatus := okta.GetVerificationStatus(authUser.Email, userVerfiyURL)
	log.Info().Msgf("Okta Verify Result for user %s -- %s", authUser.Email, strconv.FormatBool(verificationStatus))

	ip := net.ParseIP(strings.Split(vars.Endpoint, ":")[0])
	if viper.GetBool("splunk.enabled") {
		// Set up splunk client
		splunk := splunk.NewClient(
			nil,
			"https://"+viper.GetString("splunk.server")+"/services/collector",
			viper.GetString("splunk.token"),
			viper.GetString("splunk.source"),
			viper.GetString("splunk.sourcetype"),
			viper.GetString("splunk.index"),
		)
		var i interface{}

		m := map[string]string{"msg": "VPN auth request", "profile": authUser.ProfileName, "email": authUser.Email, "endpoint": vars.Endpoint, "result": strconv.FormatBool(verificationStatus)}
		i = m
		err := splunk.Log(i)
		if err != nil {
			log.Error().Err(err)
		}
	}

	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to open database!")
	}
	defer db.Close()

	location, err := db.City(ip)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to locate IP")
	}

	if viper.GetBool("loki.enabled") {
		labels := make(map[string]string)
		labels["source"] = "wireguard-vpn"
		labels["job"] = "vpn"

		cfg := promtail.ClientConfig{
			PushURL:            viper.GetString("loki.pushURL"),
			Authorization:      viper.GetString("loki.basicAuth"),
			Labels:             labels,
			BatchWait:          1 * time.Second,
			BatchEntriesNumber: 1000,
			SendLevel:          promtail.INFO,
			PrintLevel:         promtail.INFO,
		}
		loki, err := promtail.NewClientJson(cfg)
		if err != nil {
			log.Error().Err(err).Msg("Promtail client error")
		}
		defer loki.Shutdown()

		writer := promtail.CustomWriter{Client: loki}
		logger := zerolog.New(writer).With().Timestamp().Logger()
		logger.Info().Str("msg", "VPN auth request").
			Str("profile", authUser.ProfileName).
			Str("email", authUser.Email).
			Str("endpoint", vars.Endpoint).
			Str("remoteIP", ip.String()).
			Str("city", location.City.Names["en"]).
			Float64("lat", location.Location.Latitude).
			Float64("lon", location.Location.Longitude).
			Str("county", location.Country.IsoCode).
			Str("result", strconv.FormatBool(verificationStatus)).
			Msg("MFA Result")
		time.Sleep(3 * time.Second)
	}

	if !verificationStatus {
		log.Info().Msgf("User %v not allowed", authUser.Email)
		return false
	}
	log.Info().Msgf("User %v allowed", authUser.Email)
	return true
}
