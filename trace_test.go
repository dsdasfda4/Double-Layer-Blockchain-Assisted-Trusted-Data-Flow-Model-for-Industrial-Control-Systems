package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"math/big"
	"testing"
	"time"
)

func query(t *testing.T, stub *shimtest.MockStub, args [][]byte) string {
	res := stub.MockInvoke("1", args)
	if res.Status != shim.OK {
		fmt.Println("Invoke", args, "failed", string(res.Message))
		//t.FailNow()
		return string(res.Message)
	}
	if res.Payload == nil {
		fmt.Println("Query", args, "failed to get value")
		return ""
	}
	fmt.Println(string(res.Payload))
	return string(res.Payload)
}

func invoke(t *testing.T, stub *shimtest.MockStub, args [][]byte) {
	res := stub.MockInvoke("1", args)
	if res.Status != shim.OK {
		fmt.Println("Invoke", args, "failed", string(res.Message))
		t.FailNow()
	}
}

//func sha1Sum(data []byte) []byte {
//	hasher := sha1.New()
//	hasher.Write(data)
//	return hasher.Sum(nil)
//}

func generateData(msg Message, privString string) string {
	// Sign message
	message, _ := json.Marshal(msg)
	hash := sha1Sum(message)

	privPEM, err := hex.DecodeString(privString)
	if err != nil {
		fmt.Println("Failed to decode hex string:", err)
		return ""
	}

	// 解析 PEM 以获取 DER 格式的私钥
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		fmt.Println("Failed to decode PEM block containing the key")
		return ""
	}

	// 从 DER 格式重构私钥
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse the private key:", err)
		return ""
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		fmt.Println("Failed to sign the message:", err)
		return ""
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	signatureHex := hex.EncodeToString(signature)
	fmt.Printf("Signature:\n%s\n", signatureHex)
	return signatureHex
}

func Simulate(t *testing.T) string {
	cc := new(SimpleChaincode)
	stub := shimtest.NewMockStub("ccname", cc)

	var privInfo []string
	//模拟： 创建四个证书，三个A的，一个B的, 其中B是RSA
	for i := 0; i < 3; i++ {
		// Generate key pair
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			fmt.Println("Failed to generate private key:", err)
			return ""
		}

		// Create template for certificate
		notBefore := time.Now()
		notAfter := notBefore.Add(365 * 24 * time.Hour)
		serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Example Corp."},
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// Create certificate (self-signed)
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return ""
		}

		// Export private key
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			fmt.Println("Failed to marshal private key:", err)
			return ""
		}

		// Convert DER format to PEM
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		// Output in hex
		privHex := hex.EncodeToString(privPEM)
		certHex := hex.EncodeToString(certPEM)

		fmt.Printf("Private Key %d:\n%s\n", i+1, privHex)
		fmt.Printf("Public Key %d (Certificate):\n%s\n", i+1, certHex)
		privInfo = append(privInfo, privHex, certHex)
	}

	// 生成 RSA 私钥
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	// 设置证书模板
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"自签名证书组织"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 创建自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	// 将私钥转换为 PEM 格式
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	// 将证书转换为 PEM 格式
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// 输出私钥和证书字符串
	fmt.Println("Private Key PEM:\n", string(privPem))
	fmt.Println("Certificate PEM:\n", string(certPem))
	privInfo = append(privInfo, string(privPem), string(certPem))

	// 使用a角色签名
	msg := Message{
		IP:    "192.86.21",
		Tr:    "15",
		CA:    "sa4d6a5s45as6d4a6da6d64a65sd46ad46as51sx12asx1sa1xas6a4dsadsad654a5d4as65d4as6cas",
		Info4: "info4",
		Info5: "info5",
		Info6: "info6",
		Info7: "info7",
	}
	signatureHex := generateData(msg, privInfo[0])
	message, _ := json.Marshal(msg)
	certs, _ := json.Marshal(privInfo)
	aRes := query(t, stub, [][]byte{
		[]byte("function"),
		certs,
		[]byte("s"),
		message,
		[]byte(signatureHex)})
	if aRes != "" {
		privBlock, _ := pem.Decode([]byte(privInfo[6]))
		if privBlock == nil || privBlock.Type != "RSA PRIVATE KEY" {
			fmt.Println("Unable to decode private key in PEM format")
			panic("RSA key error")
		}
		priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing private key:", err)
			panic("RSA key error")
		}
		decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, []byte(aRes), nil)
		if err != nil {
			fmt.Println("Decryption error:", err)
			return ""
		}
		fmt.Printf("Decrypted data: %s\n", decryptedMessage)
		fmt.Println("Pass")
		return "ok"
	}

	// 使用b角色签名
	msg = Message{
		IP:    "info1",
		Tr:    "info2",
		CA:    "info3",
		Info4: "info4",
		Info5: "info5",
		Info6: "info6",
		Info7: "info7", //证书
	}
	signatureHex = generateData(msg, privInfo[2])
	//msg signatureHex
	//第一个参数 把模拟的证书信息带过去
	message, _ = json.Marshal(msg)
	certs, _ = json.Marshal(privInfo)
	bRes := query(t, stub, [][]byte{
		[]byte("function"),
		certs,
		[]byte("b"),
		message,
		[]byte(signatureHex)})
	if bRes != "" {
		// 解析私钥
		privBlock, _ := pem.Decode([]byte(privInfo[6]))
		if privBlock == nil || privBlock.Type != "RSA PRIVATE KEY" {
			fmt.Println("无法解码PEM格式的私钥")
			panic("RSA秘钥错误")
		}
		priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			fmt.Println("解析私钥出错:", err)
			panic("RSA秘钥错误")
		}
		decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, []byte(bRes), nil)
		if err != nil {
			fmt.Println("解密错误:", err)
			return ""
		}
		fmt.Printf("解密后的数据: %s\n", decryptedMessage)

		fmt.Println("测试b通过")

		return "ok"
	}

	// 使用c签名
	msg = Message{
		IP:    "info1",
		Tr:    "info2",
		CA:    "info3",
		Info4: "info4",
		Info5: "info5",
		Info6: "info6",
		Info7: privInfo[5], //证书
	}
	signatureHex = generateData(msg, privInfo[4])
	//msg signatureHex
	//第一个参数 把模拟的证书信息带过去
	message, _ = json.Marshal(msg)
	certs, _ = json.Marshal(privInfo)
	cRes := query(t, stub, [][]byte{
		[]byte("function"),
		certs,
		[]byte("b"),
		message,
		[]byte(signatureHex)})
	if cRes == "验证失败" {
		fmt.Println("测试c通过")
	}
	return ""
}

func Test_Invoke(t *testing.T) {
	res := Simulate(t)
	fmt.Println("B receive data: " + res)
}
