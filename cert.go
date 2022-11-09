package applejws

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

func certKeyFunc(t *jwt.Token) (interface{}, error) {
	x5cStrS, ok := t.Header["x5c"].([]interface{})
	if !ok || len(x5cStrS) < 3 {
		return nil, fmt.Errorf("key x5c not found in header")
	}

	x5c1Str, ok := x5cStrS[1].(string)
	if !ok {
		return nil, fmt.Errorf("parse x5c cert [1] error")
	}
	x5c1Bytes, err := base64.StdEncoding.DecodeString(x5c1Str)
	if err != nil {
		return nil, fmt.Errorf("parse x5c cert [1] error")
	}
	intermCert, err := x509.ParseCertificate(x5c1Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x5c cert [1] error")
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(appleRootCer)

	_, err = intermCert.Verify(x509.VerifyOptions{Roots: rootCertPool})
	if err != nil {
		return nil, fmt.Errorf("verify x5c cert [1] error")
	}

	x5c0Str, ok := x5cStrS[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid x5cStrS[0]")
	}
	x5c0Bytes, err := base64.StdEncoding.DecodeString(x5c0Str)
	if err != nil {
		return nil, fmt.Errorf("decode x5cStrs[0] error:%v", err)
	}
	cert0, err := x509.ParseCertificate(x5c0Bytes)
	if err != nil {
		return nil, err
	}

	intermCertPool := x509.NewCertPool()
	intermCertPool.AddCert(intermCert)

	_, err = cert0.Verify(x509.VerifyOptions{
		Roots: intermCertPool,
	})
	if err != nil {
		return nil, fmt.Errorf("cert 0 verify error:%v", err)
	}

	return cert0.PublicKey, nil
}
