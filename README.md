# iot-security

##Admin Setup
#####Make sure the blockchain node is running
```bash
cd $GOPATH/github.com/dappley/go-dappley/dapp
go build
./dapp
```
#####Deploy smart contract through cli
```bash
cd cli
./cli send -from <senderAddress> -amount 1 -file "../../../iot-security/contract/iot_security.js"
```
note: <senderAddress> could be any address in your wallet with at least 1 dappley coin

#####Configure the rpc port and contract address in setup/default.conf file
```bash
vim $GOPATH/github.com/dappley/iot-security/setup/default.conf
```
#####Run setup
```bash
cd setup
go run setup.go
```

##Device Monitor
#####Make sure you are in the project root folder
```bash
cd $GOPATH/github.com/dappley/iot-security
```
#####Configure the smart contract address in conf/common.conf
```bash
vim conf/common.conf
```
#####Configure the rpc port in conf/default.conf
```bash
vim conf/default.conf
```

#####Run the IoT monitoring program. Use the following command:
```bash
go run main.go
```
