package appstorejws

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// https://www.apple.com/certificateauthority/
func init() {
	var err error
	appleCers = new(appleCerS)
	appleCers.rootCer, err = x509.ParseCertificate(appleRootCer)
	if err != nil {
		panic(fmt.Sprintf("parse apple root cert error:%v", err))
	}
	appleCers.intermediateCer, err = x509.ParseCertificate(appleimCer)
	if err != nil {
		panic(fmt.Sprintf("parse apple intermedia cert error:%v", err))
	}
}

func DecodeJWS(jwtStr string, claims jwt.Claims) (jwt.Claims, error) {
	jwtToken, err := jwt.ParseWithClaims(string(jwtStr), claims, certKeyFunc)
	if err != nil {
		return nil, fmt.Errorf("parse jwt error:%v", err)
	}
	return jwtToken.Claims, nil
}

//https://developer.apple.com/documentation/appstoreservernotifications/jwstransactiondecodedpayload
type JWSTransactionPayload struct {
	AppAccountToken             string `json:"appAccountToken"`
	BundleId                    string `json:"bundleId"`
	Environment                 string `json:"environment"`
	ExpiresDate                 int64  `json:"expiresDate"`
	InAppOwnershipType          string `json:"inAppOwnershipType"`
	IsUpgraded                  bool   `json:"isUpgraded"`
	OfferIdentifier             string `json:"offerIdentifier"`
	OfferType                   int32  `json:"offerType"`
	OriginalPurchaseDate        int64  `json:"originalPurchaseDate"`
	OriginalTransactionId       string `json:"originalTransactionId"`
	ProductId                   string `json:"productId"`
	PurchaseDate                int64  `json:"purchaseDate"`
	Quantity                    int64  `json:"quantity"`
	RevocationDate              int64  `json:"revocationDate"`
	RevocationReason            int32  `json:"revocationReason"`
	SignedDate                  int64  `json:"signedDate"`
	SubscriptionGroupIdentifier string `json:"subscriptionGroupIdentifier"`
	TransactionId               string `json:"transactionId"`
	Type                        string `json:"type"`
	WebOrderLineItemId          string `json:"webOrderLineItemId"`
}

func (jpl JWSTransactionPayload) Valid() error {
	if jpl.ExpiresDate > 0 && time.Unix(jpl.ExpiresDate/1e3, (jpl.ExpiresDate%1e3)*1e6).Before(time.Now()) {
		return fmt.Errorf("jws expired at :%d", jpl.ExpiresDate)
	}
	return nil
}
