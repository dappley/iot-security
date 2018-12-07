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
	"time"
)

type Config struct {
	SenderAddr     string
	RpcPort        int
	NodeAddr       string
	NodePubkey     string
	NodePrivateKey string
}

type CommonConfig struct{
	ContractAddr   string
}

type InfoStruct struct{
	Data 		string
	BlkHeight 	uint64 `json:",string"`
}

func main() {

	logger.SetFormatter(&logger.TextFormatter{
		FullTimestamp: true,
	})

	var filePath string
	flag.StringVar(&filePath, "f", "conf/default.conf", "config file path")
	flag.Parse()

	config, err := getConfigs(filePath)
	if err != nil {
		logger.Error("can not read config file. Error:", err)
		return
	}

	commonConfig, err := getCommonConfigs()
	if err != nil {
		logger.Error("can not read config file. Error:", err)
		return
	}

	conn := initRpcClient(config.RpcPort)
	rpcService := rpcpb.NewRpcServiceClient(conn)
	adminRpcService := rpcpb.NewAdminServiceClient(conn)
	ticker := time.NewTicker(time.Second * 5).C
	currBlkHeight, err := getBlockHeight(rpcService)
	if err != nil {
		logger.Error("Unable to get latest block height. Error:", err)
		return
	}
	logger.Info("Iot Security Monitoring software starts...")
	for {
		select {
		case <-ticker:
			blkHeight, err := getBlockHeight(rpcService)
			if err != nil {
				logger.Error("Unable to get latest block height. Error:", err)
				return
			}
			if blkHeight > currBlkHeight {
				register(adminRpcService, rpcService, config, commonConfig)
				logger.Info("Registered! BlockHeight:", blkHeight)
				currBlkHeight = blkHeight
			}
		}
	}
}

func getBlockHeight(serviceClient rpcpb.RpcServiceClient) (uint64, error) {
	bcResp, err := serviceClient.RpcGetBlockchainInfo(context.Background(), &rpcpb.GetBlockchainInfoRequest{})
	if err != nil {
		return 0, err
	}
	return bcResp.BlockHeight, nil
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

func getCommonConfigs() (CommonConfig, error) {
	file, err := os.Open("conf/common.conf")
	if err != nil {
		return CommonConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	config := CommonConfig{}
	err = decoder.Decode(&config)
	if err != nil {
		return CommonConfig{}, err
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

func register(adminServiceClient rpcpb.AdminServiceClient, rpcServiceClient rpcpb.RpcServiceClient, config Config, commonConfig CommonConfig) {

	file, err := os.Stat("contract")
	if err != nil {
		logger.Panic("Cannot access directory. Error:",err)
	}
	file.Mode().String()

	blkHeight,err := getBlockHeight(rpcServiceClient)
	if err != nil {
		logger.Panic("Unable to get latest block height. Error:", err)
	}

	info := InfoStruct{file.Mode().String(), blkHeight}
	infoBytes, err := json.Marshal(info)
	if err != nil {
		logger.Panic("Unable to parse info. Error:",err)
	}

	data := sha256.Sum256(infoBytes)
	privData, err := hex.DecodeString(config.NodePrivateKey)
	if err != nil {
		logger.Panic("Cannot decode admin private key")
	}
	signature, err := secp256k1.Sign(data[:], privData)
	sig := hex.EncodeToString(signature)

	var input util.ArgStruct
	input.Function = "register"
	input.Args = []string{string(infoBytes), config.NodeAddr, config.NodePubkey, sig}
	rawBytes, err := json.Marshal(input)

	if err != nil {
		logger.Panic("Unable to parse function")
	}
	_, err = adminServiceClient.RpcSend(context.Background(), &rpcpb.SendRequest{
		From:       config.SenderAddr,
		To:         commonConfig.ContractAddr,
		Amount:     common.NewAmount(uint64(1)).Bytes(),
		Tip:        0,
		Walletpath: client.GetWalletFilePath(),
		Data:       string(rawBytes),
	})
	if err != nil {
		logger.Panic("RPC Send failed. err:", err)
	}
}
