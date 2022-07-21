package appstorejws

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type appleCerS struct {
	rootCer, intermediateCer *x509.Certificate
}

var appleCers *appleCerS

//go:embed AppleCertificateAuthority/AppleRootCA-G3.cer
var appleRootCer []byte

//go:embed AppleCertificateAuthority/AppleWWDRCAG6.cer
var appleimCer []byte

func certKeyFunc(t *jwt.Token) (interface{}, error) {
	x5cStrS, ok := t.Header["x5c"].([]interface{})
	if !ok || len(x5cStrS) < 3 {
		return nil, fmt.Errorf("key x5c not found in header")
	}
	err := checkCert(x5cStrS[2], x5cStrS[1], appleCers)
	if err != nil {
		return nil, fmt.Errorf("checkCert error:%v", err)
	}

	rootCertPool, intermCertPool := x509.NewCertPool(), x509.NewCertPool()
	rootCertPool.AddCert(appleCers.rootCer)
	intermCertPool.AddCert(appleCers.intermediateCer)

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
	_, err = cert0.Verify(x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: intermCertPool,
	})
	if err != nil {
		return nil, fmt.Errorf("cert 0 verify error:%v", err)
	}

	return cert0.PublicKey, nil
}

func checkCert(rootCertI, intermCert interface{}, cers *appleCerS) error {
	rootCertStr, ok := rootCertI.(string)
	if !ok {
		return fmt.Errorf("assert rootCertI failed")
	}
	intermCertStr, ok := intermCert.(string)
	if !ok {
		return fmt.Errorf("assert imCertI failed")
	}

	rootCertBytes, err := base64.StdEncoding.DecodeString(rootCertStr)
	if err != nil {
		return fmt.Errorf("decode rootCertStr error:%v", err)
	}
	certRoot, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return fmt.Errorf("parse rootCertStr error:%v", err)
	}
	if !certRoot.Equal(appleCers.rootCer) {
		return fmt.Errorf("root cert not valid")
	}

	imCertBytes, err := base64.StdEncoding.DecodeString(intermCertStr)
	if err != nil {
		return fmt.Errorf("decode imCertStr error:%v", err)
	}
	certInterm, err := x509.ParseCertificate(imCertBytes)
	if err != nil {
		return fmt.Errorf("parse imCertStr error:%v", err)
	}
	if !certInterm.Equal(appleCers.intermediateCer) {
		return fmt.Errorf("intermediate cer not valid")
	}

	return nil
}
