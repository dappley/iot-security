# iot-security

##Admin Setup
1. Make sure the blockchain node is running
2. Make sure the smart contract is already deployed
3. Configure the rpc port and contrct address in setup/default.conf file
```bash
vim setup/default.conf
```
4. Run setup
```bash
cd setup
go run setup.go
```

##Device Monitor
1. Make sure you are in the project root folder
2. Run the IoT monitoring program. Use the following command:
```bash
go run iot_security.go
```
