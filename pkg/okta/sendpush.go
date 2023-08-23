package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/derrickmartinez/wireguard-auth/pkg/structs"

	"github.com/okta/okta-sdk-golang/okta"
	"github.com/okta/okta-sdk-golang/okta/query"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func GetVerificationStatus(email string, userVerifyURL string) bool {
	pollingHref := sendPushToUser(userVerifyURL)
	pushResult := waitForPush(pollingHref)
	return pushResult
}

func GetUserId(email string) string {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(viper.GetString("okta.orgUrl")), okta.WithToken(viper.GetString("okta.apikey")))
	if err != nil {
		log.Fatal().Err(err)
	}
	filter := query.NewQueryParams(query.WithQ(email))
	users, resp, err := client.User.ListUsers(filter)
	_ = resp
	if err != nil {
		log.Fatal().Err(err)
	}

	return users[0].Id
}

func GetUserPushFactorId(userID string) string {
	data := structs.VerifyPayload{}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		log.Fatal().Err(err)
	}
	body := bytes.NewReader(payloadBytes)
	req, err := http.NewRequest("GET", viper.GetString("okta.orgUrl")+"/api/v1/users/"+userID+"/factors", body)
	if err != nil {
		log.Fatal().Err(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	authHeaderValue := "SSWS " + viper.GetString("okta.apikey")
	req.Header.Set("Authorization", authHeaderValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal().Err(err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result structs.UserFactorResponse
	if err := json.Unmarshal(respBody, &result); err != nil { // Parse []byte to go struct pointer
		_ = err
		log.Fatal().Err(err)
	}
	defer resp.Body.Close()
	for _, v := range result {
		if v.FactorType == "push" {
			factorID := v.ID
			return factorID
		}
	}
	return ""
}

func sendPushToUser(userVerifyURL string) string {
	req, err := http.NewRequest("POST", userVerifyURL, nil)
	if err != nil {
		log.Fatal().Err(err)
		// handle err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	authHeaderValue := "SSWS " + viper.GetString("okta.apikey")
	req.Header.Set("Authorization", authHeaderValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal().Err(err)
		// handle err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	_ = err
	defer resp.Body.Close()
	var result structs.WaitingFactor
	// var result structs.VerifyResponse
	if err := json.Unmarshal(respBody, &result); err != nil { // Parse []byte to go struct pointer
		log.Fatal().Err(err)
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal().Err(err)
	}
	_ = b
	pollURL := result.Links.Poll.Href
	waitingForPush(pollURL)
	return pollURL
}

func waitForPush(verifyHref string) bool {
	for i := 0; i < 3; i++ {
		verified := waitingForPush(verifyHref)
		if verified.FactorResult == "SUCCESS" {
			return true
		} else {
			log.Info().Msg("waiting for 5 seconds and checking for push verification again")
			verified = waitingForPush(verifyHref)
			time.Sleep(time.Second * 5)
		}
	}
	return false
}

func waitingForPush(pollURL string) structs.WaitingFactor {
	req, err := http.NewRequest("GET", pollURL, nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "SSWS "+viper.GetString("okta.apikey"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal().Err(err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	_ = err
	defer resp.Body.Close()
	var result structs.WaitingFactor
	if err := json.Unmarshal(respBody, &result); err != nil { // Parse []byte to go struct pointer
		log.Fatal().Err(err)
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal().Err(err)
	}
	_ = b
	return result
}
