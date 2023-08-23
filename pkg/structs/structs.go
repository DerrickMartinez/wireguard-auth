package structs

import "time"

type AuthPayload struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Options  Options `json:"options"`
}
type UserIdResp struct {
	ID string `json:"id"`
}

type UserFactorResponse []struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	VendorName string `json:"vendorName"`
	Status     string `json:"status"`
}

type UserDataResponse struct {
	ID              string    `json:"id"`
	Status          string    `json:"status"`
	Created         time.Time `json:"created"`
	Activated       time.Time `json:"activated"`
	StatusChanged   time.Time `json:"statusChanged"`
	LastLogin       time.Time `json:"lastLogin"`
	LastUpdated     time.Time `json:"lastUpdated"`
	PasswordChanged time.Time `json:"passwordChanged"`
	Profile         struct {
		FirstName   string `json:"firstName"`
		LastName    string `json:"lastName"`
		Email       string `json:"email"`
		Login       string `json:"login"`
		MobilePhone string `json:"mobilePhone"`
	} `json:"profile"`
	Credentials struct {
		Password struct {
		} `json:"password"`
		RecoveryQuestion struct {
			Question string `json:"question"`
		} `json:"recovery_question"`
		Provider struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"provider"`
	} `json:"credentials"`
	Links struct {
		ResetPassword struct {
			Href string `json:"href"`
		} `json:"resetPassword"`
		ResetFactors struct {
			Href string `json:"href"`
		} `json:"resetFactors"`
		ExpirePassword struct {
			Href string `json:"href"`
		} `json:"expirePassword"`
		ForgotPassword struct {
			Href string `json:"href"`
		} `json:"forgotPassword"`
		ChangeRecoveryQuestion struct {
			Href string `json:"href"`
		} `json:"changeRecoveryQuestion"`
		Deactivate struct {
			Href string `json:"href"`
		} `json:"deactivate"`
		ChangePassword struct {
			Href string `json:"href"`
		} `json:"changePassword"`
	} `json:"_links"`
}

type VerifyPayload struct {
	StateToken string `json:"stateToken"`
}

type Options struct {
	MultiOptionalFactorEnroll bool `json:"multiOptionalFactorEnroll"`
	WarnBeforePasswordExpired bool `json:"warnBeforePasswordExpired"`
}

type OktaResponse struct {
	StateToken   string    `json:"stateToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Status       string    `json:"status"`
	FactorResult string    `json:"factorResult"`
}

type OktaResponseFull struct {
	StateToken   string    `json:"stateToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Status       string    `json:"status"`
	FactorResult string    `json:"factorResult"`
	Embedded     struct {
		User struct {
			ID      string `json:"id"`
			Profile struct {
				Login     string `json:"login"`
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
				Locale    string `json:"locale"`
				TimeZone  string `json:"timeZone"`
			} `json:"profile"`
		} `json:"user"`
		FactorTypes []struct {
			FactorType string `json:"factorType"`
			Links      struct {
				Next struct {
					Name  string `json:"name"`
					Href  string `json:"href"`
					Hints struct {
						Allow []string `json:"allow"`
					} `json:"hints"`
				} `json:"next"`
			} `json:"_links"`
		} `json:"factorTypes"`
		Factors []struct {
			ID         string `json:"id"`
			FactorType string `json:"factorType"`
			Provider   string `json:"provider"`
			VendorName string `json:"vendorName"`
			Profile    struct {
				CredentialID string `json:"credentialId"`
				DeviceType   string `json:"deviceType"`
				Keys         []struct {
					Kty string `json:"kty"`
					Use string `json:"use"`
					Kid string `json:"kid"`
					X   string `json:"x"`
					Y   string `json:"y"`
					Crv string `json:"crv"`
				} `json:"keys"`
				Name     string `json:"name"`
				Platform string `json:"platform"`
				Version  string `json:"version"`
			} `json:"profile,omitempty"`
			Links struct {
				Verify struct {
					Href  string `json:"href"`
					Hints struct {
						Allow []string `json:"allow"`
					} `json:"hints"`
				} `json:"verify"`
			} `json:"_links"`
			ProfileX struct {
				CredentialID      string      `json:"credentialId"`
				AppID             interface{} `json:"appId"`
				Version           interface{} `json:"version"`
				AuthenticatorName string      `json:"authenticatorName"`
			} `json:"profile,omitempty"`
		} `json:"factors"`
		Policy struct {
			AllowRememberDevice             bool `json:"allowRememberDevice"`
			RememberDeviceLifetimeInMinutes int  `json:"rememberDeviceLifetimeInMinutes"`
			RememberDeviceByDefault         bool `json:"rememberDeviceByDefault"`
			FactorsPolicyInfo               struct {
				Opf4Cz2RrevubiYJu4X7 struct {
					AutoPushEnabled bool `json:"autoPushEnabled"`
				} `json:"opf4cz2rrevubiYJu4x7"`
			} `json:"factorsPolicyInfo"`
		} `json:"policy"`
	} `json:"_embedded"`
	Links struct {
		Cancel struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"cancel"`
	} `json:"_links"`
}

type VerifyResponse struct {
	ExpiresAt    time.Time `json:"expiresAt"`
	Status       string    `json:"status"`
	SessionToken string    `json:"sessionToken"`
	Embedded     struct {
		User struct {
			ID      string `json:"id"`
			Profile struct {
				Login     string `json:"login"`
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
				Locale    string `json:"locale"`
				TimeZone  string `json:"timeZone"`
			} `json:"profile"`
		} `json:"user"`
	} `json:"_embedded"`
	Links struct {
		Cancel struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"cancel"`
	} `json:"_links"`
}

type WaitingFactor struct {
	FactorResult string    `json:"factorResult"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Profile      struct {
		CredentialID string `json:"credentialId"`
		DeviceType   string `json:"deviceType"`
		Keys         []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Crv string `json:"crv"`
		} `json:"keys"`
		Name     string `json:"name"`
		Platform string `json:"platform"`
		Version  string `json:"version"`
	} `json:"profile"`
	Links struct {
		Cancel struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"cancel"`
		Poll struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"poll"`
	} `json:"_links"`
}
