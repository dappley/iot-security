'use strict';

var IotSecurity = function(){

};

const keyAddrs = "allNodeAddresses";
const keyPrevInfo = "prevInfo";
const keyCurrInfo = "currInfo";
const keyBlkHeight = "blkHeight";
const keyStartingBlkHeight = "startingBlkHeight";
const keyVerificationAddrs = "verificationAddresses";
const InfoKeyHeight = "BlkHeight";
const InfoKeyData = "Data";
const adminAddr = "dHqWD1QtVqe9ioFWNUCQC2EAi6QZ9sg8Np";
var numOfBatch = 4;

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
        let nextbatch = this.getNextBatch();
        if(!nextbatch){
            this.setNextBatch();
            return;
        }

        let addrs = nextbatch.split(",");
        let i = 0;
        for(i=0;i<addrs.length;i++){
            if(!this.check(addrs[i].toString())){
               //TODO: notify user
               _log.warn("Node might be attacked! Addr:", addrs[i]);
            }
        }
    },
    setNextBatch: function() {
        let addrs = LocalStorage.get(keyAddrs);
        if (!addrs){
            return;
        }
        let addrArray = addrs.split(",");
        let numOfAddrInBatch = Math.floor(addrArray.length/numOfBatch);
        addrArray = this.shuffle(addrArray);
        let res = {};
        let i;
        for (i = 0; i < numOfBatch; i++) {
            if (i == (numOfBatch -1)){
                res[i] = addrArray.slice(i*numOfAddrInBatch).toString();
            }else{
                res[i] = addrArray.slice(i*numOfAddrInBatch, (i+1)*numOfAddrInBatch).toString();
            }
        }
        let resStr = JSON.stringify(res);
        LocalStorage.set(keyVerificationAddrs, resStr);
        LocalStorage.set(keyStartingBlkHeight, Blockchain.getCurrBlockHeight());
    },
    getNextBatch: function(){
        let startingBlkHeight = LocalStorage.get(keyStartingBlkHeight);
        if (startingBlkHeight==0){
            return "";
        }
        let nextBatchesJson = LocalStorage.get(keyVerificationAddrs);
        let nextBatches = JSON.parse(nextBatchesJson)
        if (!nextBatches){
            return "";
        }
        let index = Blockchain.getCurrBlockHeight()-startingBlkHeight-1;
        if(index >= numOfBatch){
            return "";
        }
        let batch = nextBatches[index];

        if(index == numOfBatch -1){
            this.setNextBatch();
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