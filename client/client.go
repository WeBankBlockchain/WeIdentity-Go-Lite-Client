package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

func CreateWeId(restServerIp string, restServerPort string) (*big.Int, *big.Int, string, error) {
	funcName := "createWeId"
	nonce := GenerateNonce()
	publicKeyBytes, privateKeyBytes, publicKeyBigInt, privateKeyBigInt := GenerateKeyPair()
	weid := PublicKeyToWeId(publicKeyBytes)
	encodeResponseStr, err1 := consumeCreateWeIdEncodeRestApi(restServerIp, restServerPort, publicKeyBigInt, nonce, funcName)
	if err1 != nil {
		return nil, nil, "", err1
	}
	transactResponseStr, err2 := processEncodeResponse(encodeResponseStr, restServerIp, restServerPort, funcName, nonce, privateKeyBytes)
	if err2 != nil {
		return nil, nil, "", err2
	}
	transactResponse, err3 := convertJsonToTransactResponseStruct(transactResponseStr)
	if err3 != nil {
		return nil, nil, "", err3
	}
	if transactResponse.ErrorCode != 0 {
		return nil, nil, "", errors.New(transactResponse.ErrorMessage)
	}
	fmt.Println("create weid transact response =", transactResponseStr)
	return publicKeyBigInt, privateKeyBigInt, weid, nil
}

func RegisterAuthorityIssuer(restServerIp string, restServerPort string, weid string, issuerName string, privateKeyBigInt *big.Int) error {
	funcName := "registerAuthorityIssuer"
	nonce := GenerateNonce()
	privateKeyBytes := ConvertPrivateKeyBigIntToPrivateKeyBytes(privateKeyBigInt)
	encodeResponseStr, err1 := consumeRegisterAuthorityIssuerRestApi(restServerIp, restServerPort, nonce, funcName, issuerName, weid)
	if err1 != nil {
		return err1
	}

	transactResponseStr, err2 := processEncodeResponse(encodeResponseStr, restServerIp, restServerPort, funcName, nonce, privateKeyBytes)
	if err2 != nil {
		return err2
	}
	transactResponse, err3 := convertJsonToTransactResponseStruct(transactResponseStr)
	if err3 != nil {
		return err3
	}
	if transactResponse.ErrorCode != 0 {
		return errors.New(transactResponse.ErrorMessage)
	}
	fmt.Println("register authority issuer transact response =", transactResponseStr)
	return nil
}

func RegisterCpt(restServerIp string, restServerPort string, weid string, cptJsonSchema string, cptSignature string) (uint, uint, error) {
	funcName := "registerCpt"
	nonce := GenerateNonce()
	_, privateKeyBytes, _, _ := GenerateKeyPair()
	encodeResponseStr, err1 := consumeRegisterCptRestApi(restServerIp, restServerPort, nonce, funcName, weid, cptJsonSchema, cptSignature)
	if err1 != nil {
		return 0, 0, err1
	}
	transactResponseStr, err2 := processEncodeResponse(encodeResponseStr, restServerIp, restServerPort, funcName, nonce, privateKeyBytes)
	if err2 != nil {
		return 0, 0, err2
	}
	cptTransactResponse, err3 := convertJsonToCptTransactResponseStruct(transactResponseStr)
	if err3 != nil {
		return 0, 0, err3
	}
	if cptTransactResponse.ErrorCode != 0 {
		return 0, 0, errors.New(cptTransactResponse.ErrorMessage)
	}
	cptId := cptTransactResponse.RespBody.CptId
	cptVersion := cptTransactResponse.RespBody.CptVersion
	return cptId, cptVersion, nil
}

func CreateCredentialPojo(restServerIp string, restServerPort string, claim string, issuer string, expirationDate string, cptId uint, privateKeyBigInt *big.Int) (CredentialEncodeResponse, string, error) {
	funcName := "createCredentialPojo"
	encodeResponseStr, err1 := consumeCreateCredentialEncodeRestApi("39.106.69.186", "6001", funcName, claim, cptId, issuer, expirationDate)
	if err1 != nil {
		return CredentialEncodeResponse{}, "", err1
	}

	credentialEncodeResponse, err2 := convertJsonToCredentialEncodeResponse(encodeResponseStr)
	if err2 != nil {
		return CredentialEncodeResponse{}, "", err2
	}

	if credentialEncodeResponse.ErrorCode != 0 {
		return CredentialEncodeResponse{}, "", errors.New(credentialEncodeResponse.ErrorMessage)
	}

	base64SignatureValue := credentialEncodeResponse.RespBody.Proof.SignatureValue
	signatureValue, err3 := base64.StdEncoding.DecodeString(base64SignatureValue)
	if err3 != nil {
		return CredentialEncodeResponse{}, "", err3
	}

	hashedMsg := Hash(signatureValue)
	doubleHashedMsg := Hash(hashedMsg)
	privateKeyBytes := ConvertPrivateKeyBigIntToPrivateKeyBytes(privateKeyBigInt)
	signatureBytes, err4 := SignSignature(doubleHashedMsg, privateKeyBytes)
	if err4 != nil {
		return CredentialEncodeResponse{}, "", err4
	}

	signatureBase64String := base64.StdEncoding.EncodeToString(signatureBytes)
	fmt.Println("signatureBase64String =", signatureBase64String)
	credentialEncodeResponse.RespBody.Proof.SignatureValue = signatureBase64String

	credentialJsonStr, err5 := convertCredentialEncodeResponseToJson(credentialEncodeResponse.RespBody)
	if err5 != nil {
		return CredentialEncodeResponse{}, "", err5
	}

	return credentialEncodeResponse, credentialJsonStr, nil
}

func GetWeIdDocument(restServerIp string, restServerPort string, weid string) (WeIdDocumentInvokeResponse, error) {
	funcName := "getWeIdDocument"
	invokeResponseStr, err1 := consumeGetWeIdDocumentInvokeRestApi(restServerIp, restServerPort, funcName, weid)
	if err1 != nil {
		return WeIdDocumentInvokeResponse{}, err1
	}
	fmt.Println("get WeId document response =", invokeResponseStr)

	weIdDocumentInvokeResponse, err2 := convertJsonToWeIdDocumentInvokeResponse(invokeResponseStr)
	if err2 != nil {
		return WeIdDocumentInvokeResponse{}, err2
	}

	if weIdDocumentInvokeResponse.ErrorCode != 0 {
		return WeIdDocumentInvokeResponse{}, errors.New(weIdDocumentInvokeResponse.ErrorMessage)
	}
	return weIdDocumentInvokeResponse, nil
}

func QueryAuthorityIssuer(restServerIp string, restServerPort string, weid string) (AuthorityIssuerInvokeResponse, error) {
	funcName := "queryAuthorityIssuer"
	invokeResponseStr, err1 := consumeQueryAuthorityIssuerInvokeRestApi(restServerIp, restServerPort, funcName, weid)
	if err1 != nil {
		return AuthorityIssuerInvokeResponse{}, err1
	}
	fmt.Println("query authority issuer response =", invokeResponseStr)

	authorityIssuerInvokeResponse, err2 := convertJsonToAuthorityIssuerInvokeResponse(invokeResponseStr)
	if err2 != nil {
		return AuthorityIssuerInvokeResponse{}, err2
	}

	if authorityIssuerInvokeResponse.ErrorCode != 0 {
		return AuthorityIssuerInvokeResponse{}, errors.New(authorityIssuerInvokeResponse.ErrorMessage)
	}
	return authorityIssuerInvokeResponse, nil
}

func QueryCpt(restServerIp string, restServerPort string, cptId uint) (CptInvokeResponse, error) {
	funcName := "queryCpt"
	invokeResponseStr, err1 := consumeQueryCptInvokeRestApi(restServerIp, restServerPort, funcName, cptId)
	if err1 != nil {
		return CptInvokeResponse{}, err1
	}
	fmt.Println("query cpt response =", invokeResponseStr)

	cptInvokeResponse, err2 := convertJsonToCptInvokeResponse(invokeResponseStr)
	if err2 != nil {
		return CptInvokeResponse{}, err2
	}

	if cptInvokeResponse.ErrorCode != 0 {
		return CptInvokeResponse{}, errors.New(cptInvokeResponse.ErrorMessage)
	}
	return cptInvokeResponse, nil
}

func VerifyCredentialPojo(restServerIp string, restServerPort string, credentialJsonStr string) (VerifyCredentialInvokeResponse, error) {
	funcName := "verifyCredentialPojo"
	invokeResponseStr, err1 := consumeVerifyCredentialPojo(restServerIp, restServerPort, funcName, credentialJsonStr)
	if err1 != nil {
		return VerifyCredentialInvokeResponse{}, err1
	}
	fmt.Println("verify credential pojo response =", invokeResponseStr)

	verifyCredentialInvokeResponse, err2 := convertJsonToVerifyCredentialInvokeResponse(invokeResponseStr)
	if err2 != nil {
		return VerifyCredentialInvokeResponse{}, err2
	}

	if verifyCredentialInvokeResponse.ErrorCode != 0 {
		return VerifyCredentialInvokeResponse{}, errors.New(verifyCredentialInvokeResponse.ErrorMessage)
	}

	return verifyCredentialInvokeResponse, nil
}
