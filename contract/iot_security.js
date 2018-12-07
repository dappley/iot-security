'use strict';

var IotSecurity = function(){

};

const keyAddrs = "allNodeAddresses";
const keyPrevInfo = "prevInfo";
const keyCurrInfo = "currInfo";
const keyBlkHeight = "blkHeight";

const keyVerifyTargetStartingBlkHeight = "targetStartingBlkHeight";
const keyVerifyTargetAddrs = "targetAddresses";

const keyVerifierStartingBlkHeight = "verifierStartingBlkHeight";
const keyVerifierAddrs = "verifierAddresses";

const InfoKeyHeight = "BlkHeight";
const InfoKeyData = "Data";

//should be configurable
const adminAddr = "dHqWD1QtVqe9ioFWNUCQC2EAi6QZ9sg8Np";
const numOfVerifyTargetBatch = 3;
const numOfVerifierBatch = 2;

IotSecurity.prototype = {
    register: function(info, addr, pubKey, sig){
        //check if the address is in addr list
        let addrs = LocalStorage.get(keyAddrs);
        if (!addrs.includes(addr)){
            _log.warn("Register: Address is not in the verification list");
            return false
        }

        let newBatchBlockHeight = LocalStorage.get(keyVerifyTargetStartingBlkHeight);
        if (newBatchBlockHeight===0) {
            _log.debug("Next target batch has not been set yet.")
            return false;
        }

        //verify block height info (prevent replay attack)
        if (!info[InfoKeyHeight]){
            _log.warn("Register: Block height is not found in uploaded info!");
            return false;
        }
        if (info[InfoKeyHeight] != newBatchBlockHeight){
            _log.debug("Register: Not able to upload data right now");
            _log.debug("Register: Uploaded block height:", info[InfoKeyHeight]);
            _log.debug("Register: Last possible upload block height:", newBatchBlockHeight);
            return false;
        }
        let infoString = JSON.stringify(info);
        //verify publickey and signature
        if (!this.verify(infoString, addr, pubKey, sig)){
            _log.warn("Register: Verification failed");
            return false
        }

        let data = LocalStorage.get(addr);
        let lastInfo = {};

        if (data){
            lastInfo = JSON.parse(data);
            //check block height. 1 register per block. Second register will be declined
            if (info[InfoKeyHeight] === lastInfo[keyBlkHeight] ){
                _log.warn("Register: Duplicated register");
                _log.warn("Register: CurrentBlkHeight:", info[InfoKeyHeight]);
                _log.warn("Register: LastBlkHeight:", lastInfo[keyBlkHeight]);
                return false;
            }
            lastInfo[keyPrevInfo] = lastInfo[keyCurrInfo];
        }else{
            lastInfo[keyPrevInfo] = info[InfoKeyData];
        }

        lastInfo[keyCurrInfo] = info[InfoKeyData];
        lastInfo[keyBlkHeight] = info[InfoKeyHeight];
        let result = JSON.stringify(lastInfo);
        LocalStorage.set(addr, result);
        return true
    },
    setup: function(addrs, pubKey, sig){
        if (!crypto.verifyPublicKey(adminAddr, pubKey)){
            return false;
        }
        if (!crypto.verifySignature(addrs.toString(), pubKey, sig)){
            return false;
        }

        if (LocalStorage.set(keyAddrs, addrs.toString())===1){
            return false;
        }

        this.setNextVerifierBatch();
        this.setNextVerifyTargetsBatch();

        return true;
    },
    dapp_schedule: function() {
        _log.debug("IoT Security: Verifying...");
        //get the verifier this round
        let verifierIndex = this.getNextBatchIndex(keyVerifierStartingBlkHeight, numOfVerifierBatch);
        if (verifierIndex==-1) {
            _log.debug("IoT Security: Verifier batch is not generated yet. Index could not be found. exiting...")
            this.setNextVerifierBatch();
            return false;
        }

        let nextVerifierBatch = this.getVerifierBatchByIndex(verifierIndex)
        if(!nextVerifierBatch){
            _log.debug("IoT Security: Verifier batch is not generated yet. exiting...")
            this.setNextVerifierBatch();
            return false;
        }

        //get the verify targets this round
        let targetIndex = this.getNextBatchIndex(keyVerifyTargetStartingBlkHeight, numOfVerifyTargetBatch);
        if (targetIndex==-1) {
            _log.debug("IoT Security: Verifier batch is not generated yet. Index could not be found. exiting...")
            this.setNextVerifierBatch();
            return false;
        }

        let nextbatch = this.getVerifyTargetBatchByIndex(targetIndex);
        if(!nextbatch){
            _log.debug("IoT Security: Verify targets are not generated yet. exiting...")
            this.setNextVerifyTargetsBatch();
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
        }else{
            let addrs = nextbatch.split(",");
            let i = 0;
            for(i=0;i<addrs.length;i++){
                if(!this.check(addrs[i].toString())){
                    //TODO: notify user
                    _log.warn("Node might be attacked! Addr:", addrs[i]);
                }
            }
        }
        _log.debug("IoT Security: Verification finished.")
        _log.debug("IOT SEcurity: verifier index:", verifierIndex);
        _log.debug("IOT SEcurity: target Index :", targetIndex);
        if(verifierIndex == (numOfVerifierBatch -1)){
            this.setNextVerifierBatch();
        }

        if(targetIndex == (numOfVerifyTargetBatch -1)){
            this.setNextVerifyTargetsBatch();
        }

        return true
    },
    setNextVerifyTargetsBatch: function() {
        this.setNextBatch(keyVerifyTargetAddrs, keyVerifyTargetStartingBlkHeight, numOfVerifyTargetBatch)
    },
    setNextVerifierBatch: function(){
        this.setNextBatch(keyVerifierAddrs, keyVerifierStartingBlkHeight, numOfVerifierBatch)
    },
    setNextBatch: function(resultKey, startingBlkHeightKey, numOfBatches){
        let addrs = LocalStorage.get(keyAddrs);
        if (!addrs){
            return;
        }
        let addrArray = addrs.split(",");
        let resStr = this.randomizeBatch(addrArray, numOfBatches);

        LocalStorage.set(resultKey, resStr);
        LocalStorage.set(startingBlkHeightKey, Blockchain.getCurrBlockHeight());

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
    getVerifyTargetBatchByIndex: function(index){
        return this.getBatchByIndex(keyVerifyTargetAddrs, index);
    },
    getVerifierBatchByIndex: function(index){
        return this.getBatchByIndex(keyVerifierAddrs,index);
    },
    getBatchByIndex:function(addrsKey, index){

        let nextBatchesJson = LocalStorage.get(addrsKey);
        let nextBatches = JSON.parse(nextBatchesJson)
        if (!nextBatches){
            return "";
        }
        let batch = nextBatches[index];
        return batch;
    },
    getNextBatchIndex: function(startingBlkHeightKey, numOfBatches){
        let startingBlkHeight = LocalStorage.get(startingBlkHeightKey);
        if (startingBlkHeight==0){
            return -1;
        }
        let index = Blockchain.getCurrBlockHeight()-startingBlkHeight-1;
        if(index >= numOfBatches){
            return -1;
        }
        return index
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
        let newBatchBlockHeight = LocalStorage.get(keyVerifyTargetStartingBlkHeight);
        if (info[keyBlkHeight] != newBatchBlockHeight){
            _log.warn("Check: Uploaded data is out of date. Addr:", addr);
            _log.warn("Check: Block height when data is uploaded:", info[keyBlkHeight]);
            _log.warn("Check: Starting Block height of current batch:", newBatchBlockHeight);
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