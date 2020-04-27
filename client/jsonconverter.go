package client

import "encoding/json"

type EncodeResponse struct {
	RespBody     *RespBody
	ErrorCode    int
	ErrorMessage string
}

type RespBody struct {
	Data               string
	EncodedTransaction string
}

type TransactResponse struct {
	RespBody     string
	ErrorCode    int
	ErrorMessage string
}

type CptTransactRespBody struct {
	CptId      uint
	CptVersion uint
}

type CptTransactResponse struct {
	RespBody     *CptTransactRespBody
	ErrorCode    int
	ErrorMessage string
}

type CredentialEncodeResponse struct {
	RespBody     *CredentialRespBody
	ErrorCode    int
	ErrorMessage string
}

type CredentialRespBody struct {
	CptId          uint                   `json:"cptId"`
	IssuanceDate   uint64                 `json:"issuanceDate"`
	Context        string                 `json:"context"`
	Claim          map[string]interface{} `json:"claim"`
	Id             string                 `json:"id"`
	Proof          *ProofStruct           `json:"proof"`
	Type           []string               `json:"type"`
	Issuer         string                 `json:"issuer"`
	ExpirationDate uint64                 `json:"expirationDate"`
}

type ProofStruct struct {
	Created        uint64                 `json:"created"`
	Creator        string                 `json:"creator"`
	Salt           map[string]interface{} `json:"salt"`
	SignatureValue string                 `json:"signatureValue"`
	Type           string                 `json:"type"`
}

type WeIdDocumentInvokeResponse struct {
	RespBody     *WeIdDocumentRespBody
	ErrorCode    int
	ErrorMessage string
}

type WeIdDocumentRespBody struct {
	Context        string
	Authentication []AuthenticationStruct
	Created        uint64
	Id             string
	PublicKey      []PublicKeyStrut
	//Service []ServiceStruct
	Updated uint64
}

type AuthenticationStruct struct {
	Type      string
	PublicKey string
}

type PublicKeyStrut struct {
	Id        string
	Type      string
	Owner     string
	PublicKey string
}

type AuthorityIssuerInvokeResponse struct {
	RespBody     *AuthorityIssuerRespBody
	ErrorCode    int
	ErrorMessage string
}

type AuthorityIssuerRespBody struct {
	AccValue string
	Created  uint64
	Name     string
	WeId     string
}

type CptInvokeResponse struct {
	RespBody     *CptRespBody
	ErrorCode    int
	ErrorMessage string
}

type CptRespBody struct {
	CptBaseInfo   *CptBaseInfoStruct
	CptJsonSchema map[string]interface{}
	MetaData      MetaDataStruct
}

type CptBaseInfoStruct struct {
	CptId      uint
	CptVersion uint
}

type MetaDataStruct struct {
	CptPublisher string
	CptSignature string
	Created      uint64
	Updated      uint64
}

type VerifyCredentialInvokeResponse struct {
	RespBody     bool
	ErrorCode    int
	ErrorMessage string
}

func convertJsonToTransactResponseStruct(jsonStr string) (TransactResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := TransactResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToEncodeResponseStruct(jsonStr string) (EncodeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := EncodeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToCptTransactResponseStruct(jsonStr string) (CptTransactResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := CptTransactResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToCredentialEncodeResponse(jsonStr string) (CredentialEncodeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := CredentialEncodeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertCredentialEncodeResponseToJson(credentialRespBody *CredentialRespBody) (string, error) {
	jsonBytes, err := json.Marshal(credentialRespBody)
	if err != nil {
		return "", err
	}
	jsonStr := string(jsonBytes)
	return jsonStr, nil
}

func convertJsonToWeIdDocumentInvokeResponse(jsonStr string) (WeIdDocumentInvokeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := WeIdDocumentInvokeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToAuthorityIssuerInvokeResponse(jsonStr string) (AuthorityIssuerInvokeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := AuthorityIssuerInvokeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToCptInvokeResponse(jsonStr string) (CptInvokeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := CptInvokeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}

func convertJsonToVerifyCredentialInvokeResponse(jsonStr string) (VerifyCredentialInvokeResponse, error) {
	jsonBytes := []byte(jsonStr)
	response := VerifyCredentialInvokeResponse{}
	err := json.Unmarshal(jsonBytes, &response)
	if err != nil {
		return response, err
	}
	return response, nil
}
