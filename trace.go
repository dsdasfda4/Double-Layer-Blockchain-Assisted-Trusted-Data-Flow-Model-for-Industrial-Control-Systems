package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"math/big"
)

type Message struct {
	IP    string
	Tr    string
	CA    string
	Info4 string
	Info5 string
	Info6 string
	Info7 string
}

func sha1Sum(data []byte) []byte {
	hasher := sha1.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

type SimpleChaincode struct {
}

// 该函数没有初始化被系统调用一次，本系统无需初始化内容
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	//获取模拟证书
	var certs []string
	_, args := stub.GetFunctionAndParameters()
	err := json.Unmarshal([]byte(args[0]), &certs)
	if err != nil {
		return shim.Error(err.Error())
	}

	message := args[2]
	hash := sha1Sum([]byte(message))

	//获取角色
	role := args[1]

	if role != "a" && role != "b" && role != "c" {
		return shim.Error("角色参数错误")
	}

	if role == "c" {
		return shim.Error("无权限查看")
	}

	if role == "s" {

		aCert := certs[1]
		certPEM, err := hex.DecodeString(aCert)
		if err != nil {
			fmt.Println("Failed to decode hex string:", err)
			return shim.Error(err.Error())
		}

		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Println("Failed to decode PEM block containing the certificate")
			return shim.Error("Failed to decode PEM block containing the certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("Failed to parse the certificate:", err)
			return shim.Error(err.Error())
		}
		signature, err := hex.DecodeString(args[3])
		if err != nil {
			return shim.Error(err.Error())
		}
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)
		rInt := new(big.Int).SetBytes(signature[:len(signature)/2])
		sInt := new(big.Int).SetBytes(signature[len(signature)/2:])
		if !ecdsa.Verify(pubKey, hash, rInt, sInt) {
			return shim.Error("fail")
		}
	}

	if role == "b" {
		//获取该角色对应的证书
		aCert := certs[3]
		certPEM, err := hex.DecodeString(aCert)
		if err != nil {
			fmt.Println("Failed to decode hex string:", err)
			return shim.Error(err.Error())
		}

		// 解析 PEM 以获取 DER 格式的证书
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Println("Failed to decode PEM block containing the certificate")
			return shim.Error("Failed to decode PEM block containing the certificate")
		}

		// 从 DER 格式解析 X509 证书
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("Failed to parse the certificate:", err)
			return shim.Error(err.Error())
		}
		signature, err := hex.DecodeString(args[3])
		if err != nil {
			return shim.Error(err.Error())
		}
		// 提取公钥
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)
		rInt := new(big.Int).SetBytes(signature[:len(signature)/2])
		sInt := new(big.Int).SetBytes(signature[len(signature)/2:])
		if !ecdsa.Verify(pubKey, hash, rInt, sInt) {
			return shim.Error("验证失败")
		}
	}

	//使用B的RSA公钥加密
	// 解析证书
	certBlock, _ := pem.Decode([]byte(certs[7]))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fmt.Println("无法解码PEM格式的证书")
		return shim.Error("RSA加密失败")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("解析证书出错:", err)
		return shim.Error("RSA加密失败")
	}
	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, cert.PublicKey.(*rsa.PublicKey), []byte(message), nil)
	if err != nil {
		fmt.Println("加密错误:", err)
		return shim.Error("RSA加密失败")
	}
	//fmt.Printf("加密后的数据: %x\n", encryptedMessage)

	return shim.Success(encryptedMessage)

}

// args[0]: id, args[1]: hash
func (t *SimpleChaincode) document(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	err := stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

// query callback representing the query of a chaincode
func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	key := args[0]
	c, _ := stub.GetState(key)
	return shim.Success(c)
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
