package vm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dappley/go-dappley/core"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"

	"crypto/sha256"
	"github.com/dappley/go-dappley/crypto/keystore/secp256k1"
)

type InfoStruct struct{
	Data 		string
	BlkHeight 	uint64 `json:",string"`
}

func TestIotSecurity(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	script, _ := ioutil.ReadFile("../../iot-security/contract/iot_security.js")
	sc := NewV8Engine()
	ss := make(map[string]string)
	sc.ImportSourceCode(string(script))
	sc.ImportLocalStorage(ss)
	sc.ImportCurrBlockHeight(2)
	sc.ImportSeed(130)
	sc.ImportNodeAddress(core.Address{"dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP"})

	adminPubKey := "7c74f836ddeba3f813c5c298d7f67d65da012b04c51f2e13bad6a734696a692f1db40731630310910c69163695e959b0f61f4caf05626583af8a4a1bd41096aa"
	adminPrivKey := "21e4861b11bd646aa7c5807af8285c57bc8bec82b690c5ceaea482afb4da4589"
	addrStrs := []string{"dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP",
		"dRE5XUM2demeG8unwsWgs1WRGSUGdgWaDo",
		"dHvB2CF9PUtih7VM1VUZmf3g25ZGfNym5A",
		"dEhFf5mWTSe67mbemZdK3WiJh8FcCayJqm",
		"dbaifMKTn5CLG1MJCcJAvFC1SfaK9RyoVY",
		"dFR8YddUqZeKrhtBAsZLCGQoq2BkzvcRKp",
		"dWhJ1h33pC2qoqqFQcVpQVD8bPdFZP2h5B",
		"dFiE5FR1CsthtPvqVwQhpQxME7rV9ptQBb",
		"dQ75PF7y8Q56CPXFPiZ5dr5e1gVJtUvpZh"}
	addrsContent := strings.Join(addrStrs, ",")
	addrArray := []string{}
	for _, addr := range addrStrs {
		addrArray = append(addrArray, fmt.Sprintf("\"%s\"", addr))
	}
	addrs := strings.Join(addrArray, ",")

	data := sha256.Sum256([]byte(addrsContent))
	privData, err := hex.DecodeString(adminPrivKey)
	assert.Nil(t, err)
	signature, err := secp256k1.Sign(data[:], privData)
	sig := hex.EncodeToString(signature)
	assert.Nil(t, err)

	assert.Equal(t,
		"true",
		sc.Execute("setup",
			fmt.Sprintf("[%s],\"%s\",\"%s\"", addrs, adminPubKey, sig)),
	)

	nodePubKey1 := "fd2681827b0e3be73d21e3238b155fce269d7c356f2b85a74a6b0bf6514cbd345dc848a7dad99d7d61dbd8a5e08ac0b21a52b8fc575e29af6f9e089b1bbb7c82"
	nodePrivateKey1 := "f22bac4a73a9881d523075d9bb749ca537c7fa451366d935bcb65509968ac3e4"
	nodeAddr1 := "dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP"

	info := InfoStruct{"hello world", 2}
	infoBytes, err := json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	//register will fail since it is not the time to verify next batch yet
	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//block height increased, the node can register again
	sc.ImportCurrBlockHeight(3)
	//register the original message should fail since its blkHeight is still 2
	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//now it should succeed after the block height is updated
	info.BlkHeight = 3
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"true",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("check",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	//check should still return true
	sc.ImportCurrBlockHeight(4)
	assert.Equal(t,
		"true",
		sc.Execute("check",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	//node 1 register for blk height 4.
	info.BlkHeight = 4
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	//it will return false since its not next batch yet
	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//set next batch
	assert.Equal(t,
		"\"\"",
		sc.Execute("setNextVerifyTargetsBatch", ""),
	)

	//go to next block and get next batch
	sc.ImportCurrBlockHeight(5)
	info.BlkHeight = 5
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	//now it should return true
	assert.Equal(t,
		"true",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	nextBatch1 := sc.Execute("getNextVerifyTargetBatch", "")
	assert.NotEqual(t, "\"\"", nextBatch1)

	//check the batch
	assert.Equal(t,
		"false",
		sc.Execute("dapp_schedule", ""),
	)

	//go to next block and get next batch
	sc.ImportCurrBlockHeight(6)
	nextBatch2 := sc.Execute("getNextVerifyTargetBatch", "")
	assert.NotEqual(t, "\"\"", nextBatch2)
	assert.NotEqual(t, nextBatch1, nextBatch2)

	assert.Equal(t,  "dRE5XUM2demeG8unwsWgs1WRGSUGdgWaDo,dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP,dEhFf5mWTSe67mbemZdK3WiJh8FcCayJqm",
		sc.Execute("getNextVerifierBatch", ""),
	)

	//check the batch
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule", ""),
	)

	//go to next block and get next batch
	sc.ImportCurrBlockHeight(7)

	//check the batch. this is not the node's turn to be the verifier. so return false
	assert.Equal(t,
		"false",
		sc.Execute("dapp_schedule", ""),
	)

	sc.ImportNodeAddress(core.Address{})
	//check the batch. the node does not have an address, so return false
	assert.Equal(t,
		"false",
		sc.Execute("dapp_schedule", ""),
	)
}

func TestIotSecurity_randomizeBatch(t *testing.T) {

	script, _ := ioutil.ReadFile("../../iot-security/contract/iot_security.js")
	sc := NewV8Engine()
	ss := make(map[string]string)
	sc.ImportSourceCode(string(script))
	sc.ImportLocalStorage(ss)
	sc.ImportCurrBlockHeight(2)
	sc.ImportSeed(130)
	sc.ImportNodeAddress(core.Address{"testAddr"})
	arr := []string{"1","2","3","4","5","6","7","8"}
	var arrTemp []string
	for _, addr := range arr {
		arrTemp = append(arrTemp, fmt.Sprintf("\"%s\"", addr))
	}
	arrStr := strings.Join(arrTemp, ",")

	assert.Equal(t,
		"{\"0\":\"2,1\",\"1\":\"4,6\",\"2\":\"7,8\",\"3\":\"5,3\"}",
		sc.Execute("randomizeBatch",
			fmt.Sprintf("[%s],4", arrStr)),
	)

}

func signData(input []byte, privkey string) (string, error){

	data := sha256.Sum256(input)
	privData, err := hex.DecodeString(privkey)
	if err!=nil {
		return "" , err
	}
	signature, err := secp256k1.Sign(data[:], privData)
	if err!=nil {
		return "" , err
	}
	sig := hex.EncodeToString(signature)
	return sig,nil
}

func TestMakeKeys(t *testing.T) {
	kp := core.NewKeyPair()

	fmt.Println(hex.EncodeToString(kp.PublicKey))
	privateKey, _ := secp256k1.FromECDSAPrivateKey(&kp.PrivateKey)
	fmt.Println(hex.EncodeToString(privateKey))
	pkh, err := core.NewUserPubKeyHash(kp.PublicKey)
	assert.Nil(t, err)
	addr := pkh.GenerateAddress()
	fmt.Println(addr)
}

func TestIotSecurity2(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	script, _ := ioutil.ReadFile("../../iot-security/contract/iot_security.js")
	sc := NewV8Engine()
	ss := make(map[string]string)
	sc.ImportSourceCode(string(script))
	sc.ImportLocalStorage(ss)
	sc.ImportCurrBlockHeight(2)
	sc.ImportSeed(130)
	sc.ImportNodeAddress(core.Address{"dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP"})

	adminPubKey := "7c74f836ddeba3f813c5c298d7f67d65da012b04c51f2e13bad6a734696a692f1db40731630310910c69163695e959b0f61f4caf05626583af8a4a1bd41096aa"
	adminPrivKey := "21e4861b11bd646aa7c5807af8285c57bc8bec82b690c5ceaea482afb4da4589"
	addrStrs := []string{"dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP",
		"dRE5XUM2demeG8unwsWgs1WRGSUGdgWaDo",
		"dHvB2CF9PUtih7VM1VUZmf3g25ZGfNym5A",
		"dEhFf5mWTSe67mbemZdK3WiJh8FcCayJqm",
		"dbaifMKTn5CLG1MJCcJAvFC1SfaK9RyoVY",
		"dFR8YddUqZeKrhtBAsZLCGQoq2BkzvcRKp",
		"dWhJ1h33pC2qoqqFQcVpQVD8bPdFZP2h5B",
		"dFiE5FR1CsthtPvqVwQhpQxME7rV9ptQBb",
		"dQ75PF7y8Q56CPXFPiZ5dr5e1gVJtUvpZh"}
	addrsContent := strings.Join(addrStrs, ",")
	addrArray := []string{}
	for _, addr := range addrStrs {
		addrArray = append(addrArray, fmt.Sprintf("\"%s\"", addr))
	}
	addrs := strings.Join(addrArray, ",")

	data := sha256.Sum256([]byte(addrsContent))
	privData, err := hex.DecodeString(adminPrivKey)
	assert.Nil(t, err)
	signature, err := secp256k1.Sign(data[:], privData)
	sig := hex.EncodeToString(signature)
	assert.Nil(t, err)

	assert.Equal(t,
		"true",
		sc.Execute("setup",
			fmt.Sprintf("[%s],\"%s\",\"%s\"", addrs, adminPubKey, sig)),
	)

	nodePubKey1 := "fd2681827b0e3be73d21e3238b155fce269d7c356f2b85a74a6b0bf6514cbd345dc848a7dad99d7d61dbd8a5e08ac0b21a52b8fc575e29af6f9e089b1bbb7c82"
	nodePrivateKey1 := "f22bac4a73a9881d523075d9bb749ca537c7fa451366d935bcb65509968ac3e4"
	nodeAddr1 := "dGGG6kfCL1MtGgaHXAJJXDJ4KxLSD2EdEP"

	info := InfoStruct{"hello world", 2}
	infoBytes, err := json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	//register
	assert.Equal(t,
		"true",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)
	fmt.Println("====================BLOCK 3==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(3)
	//register the original message should fail since its blkHeight is still 2
	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 3
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)
	fmt.Println("====================BLOCK 4==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(4)
	//register the original message should fail since its blkHeight is still 2
	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)
	fmt.Println("====================BLOCK 5==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(5)
	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 4
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	fmt.Println("====================BLOCK6==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(6)
	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 5
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"true",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	fmt.Println("====================BLOCK7==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(7)
	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 6
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	fmt.Println("====================BLOCK8==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(8)
	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 7
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"false",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)

	fmt.Println("====================BLOCK9==================")
	//block height increased, the node can not register due to duplicated registration
	sc.ImportCurrBlockHeight(9)
	//the block height is correct, but its not the time to register yet. needs to wait until height 5
	info.BlkHeight = 8
	infoBytes, err = json.Marshal(info)
	assert.Nil(t, err)
	sig, err = signData(infoBytes, nodePrivateKey1)
	assert.Nil(t, err)

	assert.Equal(t,
		"true",
		sc.Execute("register",
			fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"", string(infoBytes), nodeAddr1, nodePubKey1, sig)),
	)

	//check should return true
	assert.Equal(t,
		"true",
		sc.Execute("dapp_schedule",
			fmt.Sprintf("\"%s\"", nodeAddr1)),
	)
}