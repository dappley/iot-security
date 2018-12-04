package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dappley/go-dappley/client"
	"github.com/dappley/go-dappley/common"
	"github.com/dappley/go-dappley/crypto/keystore/secp256k1"
	"github.com/dappley/go-dappley/rpc/pb"
	"github.com/dappley/go-dappley/util"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"log"
	"os"
	"strings"
)

type Config struct {
	RpcPort        int
	SenderAddr     string
	ContractAddr   string
	AdminPubKey    string
	AdminPrivKey   string
	Addresses      []string
}

func main() {

	logger.SetFormatter(&logger.TextFormatter{
		FullTimestamp: true,
	})

	var filePath string
	flag.StringVar(&filePath, "f", "default.conf", "config file path")
	flag.Parse()

	config, err := getConfigs(filePath)
	if err != nil {
		logger.Error("can not read config file. Error:", err)
		return
	}

	conn := initRpcClient(config.RpcPort)
	adminRpcService := rpcpb.NewAdminServiceClient(conn)
	initialSetup(adminRpcService, config)
}

func getConfigs(filePath string) (Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	config := Config{}
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func initRpcClient(port int) *grpc.ClientConn {
	//prepare grpc client
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(fmt.Sprint(":", port), grpc.WithInsecure())
	if err != nil {
		log.Panic("ERROR: Not able to connect to RPC server. ERR:", err)
	}
	return conn
}

func initialSetup(serviceClient rpcpb.AdminServiceClient, config Config) {

	addrsContent := strings.Join(config.Addresses, ",")
	data := sha256.Sum256([]byte(addrsContent))
	privData, err := hex.DecodeString(config.AdminPrivKey)
	if err != nil {
		logger.Panic("Cannot decode admin private key")
	}
	signature, err := secp256k1.Sign(data[:], privData)
	sig := hex.EncodeToString(signature)

	addrArray := []string{}
	for _, addr := range config.Addresses {
		addrArray = append(addrArray, fmt.Sprintf("\"%s\"", addr))
	}
	addrs := strings.Join(addrArray, ",")

	var input util.ArgStruct
	input.Function = "setup"
	input.Args = []string{
		fmt.Sprintf("[%s]", addrs),
		config.AdminPubKey,
		sig,
	}
	rawBytes, err := json.Marshal(input)

	if err != nil {
		logger.Panic("Unable to parse function")
	}

	_, err = serviceClient.RpcSend(context.Background(), &rpcpb.SendRequest{
		From:       config.SenderAddr,
		To:         config.ContractAddr,
		Amount:     common.NewAmount(uint64(1)).Bytes(),
		Tip:        0,
		Walletpath: client.GetWalletFilePath(),
		Data:       string(rawBytes),
	})
	if err != nil {
		logger.Panic("RPC Send failed. err:", err)
	}
}

