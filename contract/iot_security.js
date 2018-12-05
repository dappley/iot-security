'use strict';

var IotSecurity = function(){

};

const keyAddrs = "allNodeAddresses";
const keyPrevInfo = "prevInfo";
const keyCurrInfo = "currInfo";
const keyBlkHeight = "blkHeight";

const keyVerifyTargetGenerationBlkHeight = "startingBlkHeight";
const keyVerifyTargetAddrs = "verificationAddresses";

const keyVerifierGenerationBlkHeight = "startingBlkHeight";
const keyVerifierAddrs = "verifierAddresses";

const InfoKeyHeight = "BlkHeight";
const InfoKeyData = "Data";

//should be configurable
const adminAddr = "dHqWD1QtVqe9ioFWNUCQC2EAi6QZ9sg8Np";
const numOfVerifyTargetBatch = 4;
const numOfVerifierBatch = 3;

IotSecurity.prototype = {
    register: function(info, addr, pubKey, sig){
        //check if the address is in addr list
        let addrs = LocalStorage.get(keyAddrs);
        if (!addrs.includes(addr)){
            _log.warn("Register: Address is not in the verification list");
            return false
        }

        //verify block height info (prevent replay attack)
        let currBlkHeight = Blockchain.getCurrBlockHeight();
        if (!info[InfoKeyHeight]){
            _log.warn("Register: Block height is not found in uploaded info!");
            return false;
        }
        if (info[InfoKeyHeight] != currBlkHeight){
            _log.warn("Register: Uploaded block height is not equal to the current block height");
            _log.warn("Register: Uploaded block height:", info[InfoKeyHeight]);
            _log.warn("Register: Current block height:", currBlkHeight);
            return false;
        }
        let infoString = JSON.stringify(info);
        //verify publickey and signature
        if (!this.verify(infoString, addr, pubKey, sig)){
            _log.warn("Register: Verification failed");
            return false
        }

        let data = LocalStorage.get(addr);
        let jsonObj = {};

        if (data){
            jsonObj = JSON.parse(data);
            //check block height. 1 register per block. Second register will be declined
            if (currBlkHeight <= jsonObj[keyBlkHeight] ){
                _log.warn("Register: Duplicated register");
                _log.warn("Register: CurrentBlkHeight:", currBlkHeight);
                _log.warn("Register: LastBlkHeight:", jsonObj[keyBlkHeight]);
                return false;
            }
            jsonObj[keyPrevInfo] = jsonObj[keyCurrInfo];
                    }else{
            jsonObj[keyPrevInfo] = info[InfoKeyData];
        }

        jsonObj[keyCurrInfo] = info[InfoKeyData];
        jsonObj[keyBlkHeight] = currBlkHeight;
        let result = JSON.stringify(jsonObj);
        LocalStorage.set(addr, result);
        return true
    },
    setup: function(addrs, pubKey, sig){
        if (!crypto.verifyPublicKey(adminAddr, pubKey)){
            return 1;
        }
        if (!crypto.verifySignature(addrs.toString(), pubKey, sig)){
            return 1;
        }
        return LocalStorage.set(keyAddrs, addrs.toString());
    },
    dapp_schedule: function() {
        _log.debug("IoT Security: Verifying...");
        //get the verifier this roung
        let nextVerifierBatch = this.getNextVerifierBatch()
        if(!nextVerifierBatch){
            _log.debug("IoT Security: Verifier batch is not generated yet. exiting...")
            this.setNextVerifierBatch();
            return false;
        }

        //check if the node should do the verification this round
        let nodeAddr = Blockchain.getNodeAddress();
        if (!nodeAddr) {
            _log.debug("IoT Security: Node address is not set. exiting...")
            return false;
        }

        if(!nextVerifierBatch.includes(nodeAddr)){
            _log.debug("IoT Security: This node is not the verifier this round. exiting...")
            return false;
        }

        let nextbatch = this.getNextVerifyTargetBatch();
        if(!nextbatch){
            _log.debug("IoT Security: Verify targets are not generated yet. exiting...")
            this.setNextVerifyTargetsBatch();
            return false;
        }

        let addrs = nextbatch.split(",");
        let i = 0;
        for(i=0;i<addrs.length;i++){
            if(!this.check(addrs[i].toString())){
               //TODO: notify user
               _log.warn("Node might be attacked! Addr:", addrs[i]);
            }
        }
        _log.debug("IoT Security: Verification finished.")
        return true
    },
    setNextVerifyTargetsBatch: function() {
        this.setNextBatch(keyVerifyTargetAddrs, keyVerifyTargetGenerationBlkHeight, numOfVerifyTargetBatch)
    },
    setNextVerifierBatch: function(){
        this.setNextBatch(keyVerifierAddrs, keyVerifierGenerationBlkHeight, numOfVerifierBatch)
    },
    setNextBatch: function(resultKey, generationBlkHeightKey, numOfBatches){
        let addrs = LocalStorage.get(keyAddrs);
        if (!addrs){
            return;
        }
        let addrArray = addrs.split(",");
        let resStr = this.randomizeBatch(addrArray, numOfBatches);

        LocalStorage.set(resultKey, resStr);
        LocalStorage.set(generationBlkHeightKey, Blockchain.getCurrBlockHeight());

    },
    randomizeBatch: function(inputArr, numOfBatches){
        let numOfAddrInBatch = Math.floor(inputArr.length/numOfBatches);
        let resArr = this.shuffle(inputArr);
        let res = {};
        let i;
        for (i = 0; i < numOfBatches; i++) {
            if (i == (numOfBatches -1)){
                res[i] = resArr.slice(i*numOfAddrInBatch).toString();
            }else{
                res[i] = resArr.slice(i*numOfAddrInBatch, (i+1)*numOfAddrInBatch).toString();
            }
        }
        let resStr = JSON.stringify(res);
        return resStr;
    },
    getNextVerifyTargetBatch: function(){
        return this.getNextBatch(keyVerifyTargetAddrs, keyVerifyTargetGenerationBlkHeight, numOfVerifyTargetBatch);
    },
    getNextVerifierBatch: function(){
        return this.getNextBatch(keyVerifierAddrs, keyVerifierGenerationBlkHeight, numOfVerifierBatch);
    },
    getNextBatch:function(addrsKey, generationBlkHeightKey, numOfBatches){
        let startingBlkHeight = LocalStorage.get(generationBlkHeightKey);
        if (startingBlkHeight==0){
            return "";
        }
        let nextBatchesJson = LocalStorage.get(addrsKey);
        let nextBatches = JSON.parse(nextBatchesJson)
        if (!nextBatches){
            return "";
        }
        let index = Blockchain.getCurrBlockHeight()-startingBlkHeight-1;
        if(index >= numOfBatches){
            return "";
        }
        let batch = nextBatches[index];

        if(index == numOfBatches -1){
            this.setNextBatch(addrsKey, generationBlkHeightKey, numOfBatches);
        }
        return batch;
    },
    verify: function(msg, addr, pubKey, sig){
        if (!crypto.verifyPublicKey(addr, pubKey)){
            _log.warn("verifyPublicKey Failed!");
            return false;
        }
        if (!crypto.verifySignature(msg, pubKey, sig)){
            _log.warn("verifySignature Failed!");
            return false;
        }
        return true;
    },
    check: function(addr){
        let data = LocalStorage.get(addr);
        if (!data){
            _log.warn("Check: Node has never registered. Addr:", addr);
            return false;
        }
        let info = JSON.parse(data);
        if (info[keyPrevInfo] != info[keyCurrInfo]){
            _log.warn("Check: Uploaded data has been changed. Addr:", addr);
            _log.warn("Check: Previous data:", info[keyPrevInfo]);
            _log.warn("Check: Current data:", info[keyCurrInfo]);
            return false;
        }
        if (info[keyBlkHeight] != Blockchain.getCurrBlockHeight()){
            _log.warn("Check: Uploaded data is out of date. Addr:", addr);
            _log.warn("Check: Block height when data is uploaded:", info[keyBlkHeight]);
            _log.warn("Check: Current Block height:", Blockchain.getCurrBlockHeight());
            return false;
        }
        return true;
    },
    shuffle: function(array) {
        let currentIndex = array.length, temporaryValue, randomIndex;

        // While there remain elements to shuffle...
        while (0 !== currentIndex) {

            // Pick a remaining element...
            randomIndex = math.random(currentIndex);
            currentIndex -= 1;

            // And swap it with the current element.
            temporaryValue = array[currentIndex];
            array[currentIndex] = array[randomIndex];
            array[randomIndex] = temporaryValue;
        }

        return array;
    }
};

var iotSecurity = new IotSecurity;