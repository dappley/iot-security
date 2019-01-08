package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dappley/go-dappley/client"
	"github.com/dappley/go-dappley/common"
	"github.com/dappley/go-dappley/rpc/pb"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io/ioutil"
	"os"
)

type Config struct {
	RpcPort        int
	SenderAddr     string
	ContractAddr   string
	AdminPubKey    string
	AdminPrivKey   string
	Addresses      []string
}

type ArgStruct struct{
	Function string `json:"function"`
	Args 	 []string `json:"args"`
}

func main() {

	logger.SetFormatter(&logger.TextFormatter{
		FullTimestamp: true,
	})

	var filePath string
	flag.StringVar(&filePath, "f", "../setup/default.conf", "config file path")
	flag.Parse()

	config, err := getConfigs(filePath)
	if err != nil {
		logger.Error("can not read config file. Error:", err)
		return
	}

	conn := initRpcClient(config.RpcPort)
	adminRpcService := rpcpb.NewAdminServiceClient(conn)
	deploy(adminRpcService, config)
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
		logger.Panic("ERROR: Not able to connect to RPC server. ERR:", err)
	}
	return conn
}

func deploy(serviceClient rpcpb.AdminServiceClient, config Config) {

	script, err := ioutil.ReadFile("iot_security.js")
	if err != nil {
		fmt.Println("Smart contract path is invalid. Path: iot_security.js")
		return
	}
	resp, err := serviceClient.RpcSend(context.Background(), &rpcpb.SendRequest{
		From:       config.SenderAddr,
		To:         "",
		Amount:     common.NewAmount(uint64(1)).Bytes(),
		Tip:        common.NewAmount(uint64(0)).Bytes(),
		WalletPath: client.GetWalletFilePath(),
		Data:       string(script),
	})
	if err != nil {
		logger.Panic("RPC Send failed. err:", err)
	}
	logger.WithFields(logger.Fields{
		"contract_addr" :	resp.ContractAddr,
	}).Info("contract has been deployed!")
}

