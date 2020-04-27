package client

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
)

func consumeCreateWeIdEncodeRestApi(restServerIp string, restServerPort string, publicKeyBigInt *big.Int, nonce string, funcName string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "encode")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg":{"publicKey":"`)
	json.WriteString(publicKeyBigInt.String())
	json.WriteString(`"},"functionName":"`)
	json.WriteString(funcName)
	json.WriteString(`","transactionArg": {"nonce": "`)
	json.WriteString(nonce)
	json.WriteString(`"},"v":"1.0.0"}`)
	fmt.Println("create weid encode request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("create weid encode response =", response)
	return response, err
}

func consumeRegisterAuthorityIssuerRestApi(restServerIp string, restServerPort string, nonce string, funcName string, name string, weid string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "encode")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg":{"name":"`)
	json.WriteString(name)
	json.WriteString(`","weId": "`)
	json.WriteString(weid)
	json.WriteString(`"},"functionName":"`)
	json.WriteString(funcName)
	json.WriteString(`","transactionArg": {"nonce": "`)
	json.WriteString(nonce)
	json.WriteString(`"},"v":"1.0.0"}`)
	fmt.Println("register authority issuer encode request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("register authority issuer encode response =", response)
	return response, err
}

func consumeRegisterCptRestApi(restServerIp string, restServerPort string, nonce string, funcName string, weid string, cptJsonSchema string, cptSignature string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "encode")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg":{"weId": "`)
	json.WriteString(weid)
	json.WriteString(`","cptJsonSchema": `)
	json.WriteString(cptJsonSchema)
	json.WriteString(`,"cptSignature": "`)
	json.WriteString(cptSignature)
	json.WriteString(`"},"functionName":"`)
	json.WriteString(funcName)
	json.WriteString(`","transactionArg": {"nonce": "`)
	json.WriteString(nonce)
	json.WriteString(`"},"v":"1.0.0"}`)
	fmt.Println("register cpt encode request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("register cpt encode response =", response)
	return response, err
}

func consumeCreateCredentialEncodeRestApi(restServerIp string, restServerPort string, funcName string, claim string, cptId uint, issuer string, expirationDate string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "encode")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg":{"cptId":`)
	json.WriteString(strconv.Itoa(int(cptId)))
	json.WriteString(`, "issuer": "`)
	json.WriteString(issuer)
	json.WriteString(`","expirationDate": "`)
	json.WriteString(expirationDate)
	json.WriteString(`","claim":`)
	json.WriteString(claim)
	json.WriteString(`},"functionName":"`)
	json.WriteString(funcName)
	json.WriteString(`", "transactionArg": {},"v":"1.0.0"}`)
	fmt.Println("create credential encode request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("create credential encode response =", response)
	return response, err
}

func consumeGetWeIdDocumentInvokeRestApi(restServerIp string, restServerPort string, funcName string, weid string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "invoke")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg": {"weId": "`)
	json.WriteString(weid)
	json.WriteString(`"}, "transactionArg": {}, "functionName": "`)
	json.WriteString(funcName)
	json.WriteString(`","v": "1.0.0"}`)
	fmt.Println("get weid document invoke request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("get weid document invoke response =", response)
	return response, err
}

func consumeQueryAuthorityIssuerInvokeRestApi(restServerIp string, restServerPort string, funcName string, weid string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "invoke")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg": {"weId": "`)
	json.WriteString(weid)
	json.WriteString(`"}, "transactionArg": {}, "functionName": "`)
	json.WriteString(funcName)
	json.WriteString(`","v": "1.0.0"}`)
	fmt.Println("query authority issuer invoke request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("query authority issuer invoke response =", response)
	return response, err
}

func consumeQueryCptInvokeRestApi(restServerIp string, restServerPort string, funcName string, cptId uint) (string, error) {
	url := getUrl(restServerIp, restServerPort, "invoke")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg": {"cptId": "`)
	json.WriteString(strconv.Itoa(int(cptId)))
	json.WriteString(`"}, "transactionArg": {}, "functionName": "`)
	json.WriteString(funcName)
	json.WriteString(`","v": "1.0.0"}`)
	fmt.Println("query cpt invoke request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("query cpt invoke response =", response)
	return response, err
}

func consumeVerifyCredentialPojo(restServerIp string, restServerPort string, funcName string, credentialJsonStr string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "invoke")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg": `)
	json.WriteString(credentialJsonStr)
	json.WriteString(`, "transactionArg": {}, "functionName": "`)
	json.WriteString(funcName)
	json.WriteString(`","v": "1.0.0"}`)
	fmt.Println("verify credential pojo invoke request =", json.String())

	response, err := consumeRestApi(url, json.String())
	fmt.Println("verify credential pojo invoke response =", response)
	return response, err
}

func consumeTransactRestApi(restServerIp string, restServerPort string, signature string, data string, nonce string, funcName string) (string, error) {
	url := getUrl(restServerIp, restServerPort, "transact")

	json := bytes.Buffer{}
	json.WriteString(`{"functionArg":{},"functionName":"`)
	json.WriteString(funcName)
	json.WriteString(`","transactionArg": {"nonce": "`)
	json.WriteString(nonce)
	json.WriteString(`","data": "`)
	json.WriteString(data)
	json.WriteString(`","signedMessage": "`)
	json.WriteString(signature)
	json.WriteString(`"},"v":"1.0.0"}`)

	response, err := consumeRestApi(url, json.String())
	return response, err
}

func consumeRestApi(url string, json string) (string, error) {
	jsonBytes := []byte(json)
	response, err1 := http.Post(url, "application/json", bytes.NewBuffer(jsonBytes))
	if err1 != nil {
		fmt.Printf("The Http request failed with error %s\n", err1)
		return "", err1
	}
	data, err2 := ioutil.ReadAll(response.Body)
	if err2 != nil {
		return "", err2
	}
	return string(data), nil
}

func getUrl(restServerIp string, restServerPort string, mappingType string) string {
	url := bytes.Buffer{}
	url.WriteString("http://")
	url.WriteString(restServerIp)
	url.WriteString(":")
	url.WriteString(restServerPort)
	url.WriteString("/weid/api/")
	url.WriteString(mappingType)
	fmt.Println(url.String())

	return url.String()
}

func processEncodeResponse(encodeResponseStr string, restServerIp string, restServerPort string, funcName string, nonce string, privateKeyBytes []byte) (string, error) {
	encodeResponse, err1 := convertJsonToEncodeResponseStruct(encodeResponseStr)
	if err1 != nil {
		return "", err1
	}
	if encodeResponse.ErrorCode != 0 {
		return "", errors.New(encodeResponse.ErrorMessage)
	}
	transaction, err2 := base64.StdEncoding.DecodeString(encodeResponse.RespBody.EncodedTransaction)
	if err2 != nil {
		return "", err2
	}
	hashedMsg := Hash(transaction)
	signatureBytes, err3 := SignSignature(hashedMsg, privateKeyBytes)
	if err3 != nil {
		return "", err3
	}

	signatureBase64Str := base64.StdEncoding.EncodeToString(signatureBytes)
	transactResponseStr, err4 := consumeTransactRestApi(restServerIp, restServerPort, signatureBase64Str, encodeResponse.RespBody.Data, nonce, funcName)
	if err4 != nil {
		return "", err4
	}
	return transactResponseStr, nil
}
