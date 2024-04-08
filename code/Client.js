const net = require('net');
const crypto = require('crypto');
const crypto1 = require('crypto-js');
const bigInt = require('big-integer');
const { MongoClient } = require('mongodb');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")
const uri = 'mongodb://localhost:27017';
const dbName = 'database1';
const collectionName = 'collection2';




class FuzzyExtractor {
    constructor(length, hamErr, repErr) {
        this.length = length;
        this.secLen = 2;
        this.numHelpers = this.calculateNumHelpers(hamErr, repErr);
        this.hashFunc = "sha256";
        this.nonceLen = 16;
    }

    parseLockerArgs() {
        this.hashFunc = "SHA-256";
        this.nonceLen = 16;
    }

    calculateNumHelpers(hamErr, repErr) {
        const bits = this.length * 8;
        const constValue = hamErr / Math.log(bits);
        const numHelpersDouble = Math.pow(bits, constValue) * Math.log(2.0 / repErr) / Math.log(2);
        return Math.round(numHelpersDouble);
    }

    generate(value) {
        const key = crypto.randomBytes(this.length);
        const keyPad = Buffer.concat([key, Buffer.alloc(this.secLen)]);

        const nonces = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.nonceLen));
        const masks = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length));
        const digests = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length + this.secLen));

        const vectors = new Array(this.numHelpers).fill().map((_, helper) => {
            const vector = Buffer.alloc(this.length);
            for (let i = 0; i < this.length; i++) {
                vector[i] = masks[helper][i] & value[i];
            }
            return vector;
        });

        const ciphers = new Array(this.numHelpers).fill().map(() => Buffer.alloc(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const dVector = vectors[helper];
            const dNonce = nonces[helper];
            const digest = this.pbkdf2Hmac(this.hashFunc, dVector, dNonce, 1, this.length + this.secLen);
            digests[helper] = digest;
        }

        for (let helper = 0; helper < this.numHelpers; helper++) {
            for (let i = 0; i < this.length + this.secLen; i++) {
                ciphers[helper][i] = digests[helper][i] ^ keyPad[i];
            }
        }

        return {
            key,
            publicHelper: {
                ciphers,
                masks,
                nonces
                //                 ciphers: ciphers.map(buf=>{return buf.toString()}),
                // masks: masks.map(buf=>{return buf.toString()}),
                // nonces: nonces.map(buf=>{return buf.toString()})
            }
        };
    }

    reproduce(value, helpers) {
        if (this.length !== value.length) {
            throw new Error("Cannot reproduce key for value of different length");
        }

        const ciphers = helpers.ciphers;
        const masks = helpers.masks;
        const nonces = helpers.nonces;

        const vectors = new Array(this.numHelpers).fill().map((_, helper) => {
            const vector = Buffer.alloc(this.length);
            for (let i = 0; i < this.length; i++) {
                vector[i] = masks[helper][i] & value[i];
            }
            return vector;
        });

        const digests = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const dVector = vectors[helper];
            const dNonce = nonces[helper];
            const digest = this.pbkdf2Hmac(this.hashFunc, dVector, dNonce, 1, this.length + this.secLen);
            digests[helper] = digest;
        }

        const plains = new Array(this.numHelpers).fill().map(() => Buffer.alloc(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            for (let i = 0; i < this.length + this.secLen; i++) {
                plains[helper][i] = digests[helper][i] ^ ciphers[helper][i];
            }
        }

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const checkBytes = plains[helper].slice(this.length, this.length + this.secLen);
            if (checkBytes.equals(Buffer.alloc(this.secLen))) {
                return plains[helper].slice(0, this.length);
            }
        }

        return null;
    }

    pbkdf2Hmac(hashFunc, value, salt, iterations, length) {
        try {
            let hmac = crypto.createHmac(hashFunc, salt); // Change const to let
            const result = Buffer.alloc(length);
            const block = Buffer.concat([salt, Buffer.alloc(4)]);
            let offset = 0;
    
            while (offset < length) {
                block.writeUInt32BE(++iterations, salt.length);
                const u = hmac.update(block).digest();
    
                for (let i = 0; i < u.length && offset < length; i++) {
                    result[offset++] = u[i];
                }
                // Recreate hmac for next iteration
                hmac = crypto.createHmac(hashFunc, salt);
            }
    
            return result;
        } catch (error) {
            console.error("Error in pbkdf2Hmac:", error);
            throw new Error("Error in pbkdf2Hmac");
        }
    }
    
    
    
    

    pack(bytes, offset, value) {
        bytes[offset + 0] = (value >> 24) & 0xFF;
        bytes[offset + 1] = (value >> 16) & 0xFF;
        bytes[offset + 2] = (value >> 8) & 0xFF;
        bytes[offset + 3] = value & 0xFF;
    }

    static KeyAndHelper(key, publicHelper) {
        this.key = key;
        this.publicHelper = publicHelper;
    }
}



class Client {
    constructor() {
        this.PORT = 1000;
        this.ID = "";
        this.SNID = "";
        this.time = "";
        this.mode = "";
        this.TH2 = "";
        this.CA = "";
        this.PI = "";
        this.GS = "";
        this.Helper = "";
        this.initializeClient();
    }


    async getInput(ques) {
        const readline = require('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        return new Promise((resolve) => {
            rl.question(ques, (input) => {
                rl.close();
                resolve(input);
            });
        });
    }

    async getData(){
        
    }

   async initializeClient() {
        const ipAddress = '127.0.0.1';
        const socket = new net.Socket();
        const ques = "Do you want to register(1) or authenticate(2): ";
        const input = await this.getInput(ques);
        socket.connect(this.PORT, ipAddress, async() => {
            console.log('Connected to server');
            if(input === '1'){
                this.mode = "Registration";
                const ques1 = "Please provide your User ID : ";
                const input1 = await this.getInput(ques1);
                this.ID = input1;
                const M1 = this.mode + " " + this.ID + " " + Date.now();
                // Send Type1 message to the Administrator
                const message1 = {
                    type: 'M1UA',
                    content: M1
                };
                this.sendMessage(socket, message1);

            }
            else{
                this.mode = "Authentication";
                const ques1 = "Please provide your User ID : ";
                const input1 = await this.getInput(ques1);
                this.ID = input1;
                const ques2 = "Please provide the ID of the Sensor node to which you want to connect : ";
                const input2 = await this.getInput(ques2);
                this.SNID = input2;
                const client = new MongoClient(uri);
                
                try {
                    // Connect to the MongoDB cluster
                    await client.connect();
                    // Access a specific database
                    const database = client.db(dbName);

                    // Access a specific collection
                    const collection = database.collection(collectionName);
                    const pI = this.ID;
                    const result = await collection.find({ clientID: pI  }).toArray();
                    const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
                    this.PI = pseudoIdentities[0];
                } catch (e) {
                    console.error('Error:', e);
                } finally {
                    // Close the client connection
                    await client.close();
                }

                // const cId = this.ID;
                const M5 =  this.mode + " " + this.PI + " " + Date.now() + " " + this.SNID;
                const message = {
                    type: 'M1UG',
                    content: M5
                };
                this.sendMessage(socket,message);
            }
        });

        socket.on('data', (data) => {
            const receivedMessage = JSON.parse(data.toString());
            this.handleServerMessage(socket, receivedMessage);
        });

        socket.on('end', () => {
            console.log('Connection closed');
        });
    }

    handleServerMessage(socket, message) {

        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'M2UA':
                this.processM2UAMessage(socket, message.content);
                break;
            case 'M4UA':
                this.processM4UAMessage(socket, message.content);
                break;
            case 'M2UG':
                this.processM2UGMessage(socket, message.content);
                break;
            case 'M4UG':
                this.processM4UGMessage(socket,message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    
    async processM4UGMessage(socket,content){

        console.log(`Processing M4UG message: ${content}`,"\n\n");

        const parts = content.split(" ");
        const Nonce = parts[0];
        const SK = parts[1];
        const PIog = parts[2];
        const T = Math.abs(Nonce- Date.now());
        if(T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");

            const client = new MongoClient(uri)
            await client.connect();
            const database = client.db("database1");
            const collection2 = database.collection("collection2");
            const collection1 = database.collection("collection1");
            const result = await collection2.find({ clientID: this.ID}).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const PI = pseudoIdentities[0];
            const result2 = await collection1.find({pseudoIdentity : PI}).toArray();
            const GSs = result2.map(entry => entry.gatewaySecret);
            const GS = GSs[0];
            const sessionKey = this.xorNumberWithString(SK,GS);
            const PInew = this.xorStrings(PIog,GS);
            const filter = { pseudoIdentity: PI };
            const updateDocument = {
                $set: {
                    pseudoIdentity: PInew
                }
            };

            // Update both collections
            await Promise.all([
                collection2.updateOne(filter, updateDocument),
                collection1.updateOne(filter, updateDocument)
            ]);
            console.log("Psuedo Identity has been updated from : ",PI," to : ",PInew,"\n\n");
            console.log("Session Key has also been generated : ",sessionKey,"(Session Key)");
        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
    async processM2UAMessage(socket, content) {
        
        console.log(`Processing M2UA message: ${content}`,"\n\n");

        const challenge = this.convertNumbersStringToByteArray(content);
        const response = this.generateResponse(challenge);
        
        const ans = response.join(' ');

        const fuzzyExtractor = new FuzzyExtractor(32, 0.01, 0.01);
        const {key,publicHelper} =  fuzzyExtractor.generate(response);

        const S2 = fuzzyExtractor.reproduce(response,publicHelper);

        const keyAndHelper = fuzzyExtractor.generate(response);
        const S1 = Buffer.from(keyAndHelper.key).toString('utf-8');
        const client = new MongoClient(uri);
        const dataToInsert = {
            clientID: this.ID,
            Helper : keyAndHelper.publicHelper
        };
        // Connect to MongoDB server
        await client.connect(async function (err) {
            console.log(err)
        })
        const db = client.db(dbName);

        const collection3 = db.collection('collection3');

        try {
            const result = await collection3.insertOne(dataToInsert);
           
            const docs = await collection3.find({}).toArray();
            
        } catch (error) {
            console.error('Error inserting data or fetching data from collection:', error);
        } finally {
            // Close the connection
            client.close();
        }

        const alpha = this.hash(S1 + this.ID);
        // console.log(alpha,"Hash generated");
        const Ru = response.toString();
        const Message_2 = alpha + " " + ans;
        
        // Send Type3 message to the Administrator
        const message3 = {
            type: 'M3UA',
            content: Message_2
        };
        this.sendMessage(socket, message3);
    }

    async processM4UAMessage(socket, content) {

        // Process Type4 message content
        console.log(`Processing Type4 message: ${content}`,"\n\n");
        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        console.log('M4UA : ',"\n");
        console.log("Transaction Hash : ",this.TH2);
        console.log("Contract Address : ",this.CA);
        console.log("Psuedo Identity :",this.PI);
        console.log("Gateway Secret :",this.GS,"\n");
        
        // Close the connection
        socket.end();
    }

    async processM2UGMessage(socket,content){

        console.log(`Processing M2UG message from Administrator: ${content}`,"\n\n");
        const client = new MongoClient(uri);

        let parts = content.split(" ");
        let j = parts[parts.length - 1];
        let Nonce = parts[0];
        let Message_7="";
        try {
            // Connect to the MongoDB cluster
            await client.connect();
            const database = client.db(dbName);

            // Access a specific collection
            const collection2 = database.collection(collectionName);
            const cID = this.ID;
            const result = await collection2.find({ clientID: cID }).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const gsecrets = result.map(entry => entry.gatewaySecret);
            const tHash1 = result.map(entry => entry.tHash);
            const cAddress1 = result.map(entry => entry.cAddress);
            this.PI = pseudoIdentities[0];
            let gatewaySecret = gsecrets[0];
            let tHash = tHash1[0];
            let cAddress = cAddress1[0];

            const fuzzyExtractor1 = new FuzzyExtractor(32, 0.01, 0.01);

            const T = Math.abs(Date.now() - Nonce);
            if (T <=100){

                console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n");
                let betaS = "";
                for(let i=1;i<parts.length-2;i++){
                    betaS += parts[i] + " ";
                }
                betaS += parts[parts.length-2];
                const beta = this.convertNumbersStringToByteArray(betaS);

                const secretBytes = [];
                for (let i = 0; i < gatewaySecret.length; i += 2) {
                    const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                    secretBytes.push(byte);
                }
                // Perform XOR operation between corresponding elements of gatewaySecretBytes and beta
                const challenge = beta.map((num, index) => num ^ secretBytes[index]);

                const response = this.generateResponse(challenge);
                const {key,publicHelper} =  fuzzyExtractor1.generate(response);
                
                const omega = this.hash(gatewaySecret + response);
                // console.log("Values for omega",gatewaySecret,response);
                j=BigInt(j)
                if(omega === j){
                    console.log("Authentication successful(AS) of Gateway at User Device !, 'omega == j' ,where omega = ",omega,"and j = ",j,"\n\n");
                }

                const fuzzyExtractor = new FuzzyExtractor(32, 0.01, 0.01);
                const S2 = fuzzyExtractor.reproduce(response,publicHelper);
                const S1 = S2.toString('hex');

                const midhash = this.hash(S1+this.ID);
                const delta = this.xorBigIntegers(midhash,gatewaySecret);

                const secretBytes1 = [];
                for (let i = 0; i < gatewaySecret.length; i += 2) {
                    const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                    secretBytes1.push(byte);
                }
                // Perform XOR operation between corresponding elements of response and gatewaySecret
                const mu = response.map((num, index) => num ^ secretBytes1[index]);
                const m5 = mu.join(' ');

                Message_7 = Date.now() + " " + delta + " " + m5 + " " + this.PI + " " + tHash + " " + cAddress;
            }
            else{
                console.log("ERROR : The Received Message is not FRESH..........");
            }

        } catch (e) {
            console.error('Error:', e);
        } finally {
            const message_7 = {
                type : 'M3UG',
                content : Message_7
            }
            this.sendMessage(socket,message_7);
            // Close the client connection
            await client.close();
        }

    }

    sendMessage(socket, message) {
        // Send the message object to the Administrator
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message ${message.type} to Administrator: ${JSON.stringify(message)}`,"\n\n");
    }

    convertNumbersStringToByteArray(numbersString) {
        const numberStrings = numbersString.split(/\s+/); // Split by one or more spaces
        const byteArray = new Uint8Array(numberStrings.length);
    
        for (let i = 0; i < numberStrings.length; i++) {
            try {
                // Convert each number string to byte and store in the array
                byteArray[i] = parseInt(numberStrings[i], 10);
            } catch (error) {
                // Handle the case where the string is not a valid byte
                console.error(error);
            }
        }
    
        return byteArray;
    }
    
    generateResponse(challenge) {
        try {
            const digest = crypto.createHash('sha256');
            return Buffer.from(digest.update(Buffer.from(challenge)).digest());
        } catch (error) {
            console.error(error);
            return null;
        }
    }
    hash(message) {
        const hash = crypto1.SHA256(message);
        return BigInt('0x' + hash.toString(crypto1.enc.Hex));
    }
    xorNumberWithString(number, str) {
        // Convert string to an array of code points
        const codePoints = Array.from(str, char => char.charCodeAt(0));
    
        // Perform XOR operation between the number and each code point
        const xorResult = codePoints.map(codePoint => number ^ codePoint);
    
        // Convert the resulting array of code points back to a string
        const resultString = String.fromCharCode(...xorResult);
    
        return resultString;
    }
    xorStrings(str1, str2) {
        // Convert strings to arrays of code points
        const arr1 = Array.from(str1, char => char.charCodeAt(0));
        const arr2 = Array.from(str2, char => char.charCodeAt(0));
        
        // Perform XOR operation on each pair of code points
        const xorResult = arr1.map((codePoint, index) => codePoint ^ arr2[index]);
        
        // Convert code points back to characters and concatenate them into a string
        const resultString = String.fromCharCode(...xorResult);
        
        return resultString;
    }
    xorBigIntegers(a, b) {
        // Convert hexadecimal strings to BigIntegers
        if (typeof a === 'string') {
            a = BigInt('0x' + a);
        }
        if (typeof b === 'string') {
            b = BigInt('0x' + b);
        }
    
        // Perform XOR operation
        return a ^ b;
    }

}

// Create an instance of the Client
const client = new Client();
