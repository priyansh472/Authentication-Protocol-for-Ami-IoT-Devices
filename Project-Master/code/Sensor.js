const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")
const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';
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
            const hmac = crypto.createHmac(hashFunc, salt);
            const result = Buffer.alloc(length);
            const block = Buffer.concat([salt, Buffer.alloc(4)]);
            let offset = 0;

            while (offset < length) {
                block.writeUInt32BE(++iterations, salt.length);
                const u = hmac.update(block).digest();

                for (let i = 0; i < u.length && offset < length; i++) {
                    result[offset++] = u[i];
                }
            }

            return result;
        } catch (error) {
            throw new Error("Error initializing crypto");
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

async function main() {
    try {
        const AS = new Sensor();
    } catch (error) {
        console.error(error);
    }
}
class Sensor{
    constructor() {
        this.PORT = 1000;
        this.ID = "";
        this.mode();
        this.challenge="";
        this.response="";
        this.alpha="";
        this.TH2 = "";
        this.CA = "";
        this.PI = "";
        this.GS = "";
        this.time = "";
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
    async mode(){
        const ques = "Do you want to register(1) or authenticate(2): ";
        const input = await this.getInput(ques);
        switch(input){
            case '1':
                this.initializeServer();
                break;
            case '2':
                this.initializeSensor();
                break;
            default:
                console.log(`Unknown message type: ${input}`);
        }

    }
    async initializeSensor(){
        const ques1 = "Please provide the Sensor ID to be registered : ";
        const input = await this.getInput(ques1);
        this.ID = input;
        const server = net.createServer((socket) => {
            socket.on('data', (data) => {
                const receivedMessage = JSON.parse(data.toString());
                this.handleSensorMessage(socket, receivedMessage);
            });

            socket.on('end', () => {
                console.log('Sensor disconnected');
            });
        });

        server.listen(2000, () => {
            console.log(`\n\nServer listening on port 2000 to process sensor authentication\n\n`);
        });
    }

    async initializeServer() {
        const ques1 = "Please provide the Sensor ID to be registered : ";
        const input = await this.getInput(ques1);
        this.ID = input;
        const server = net.createServer((socket) => {
            socket.on('data', (data) => {
                const receivedMessage = JSON.parse(data.toString());
                this.handleClientMessage(socket, receivedMessage);
            });

            socket.on('end', () => {
                console.log('Admin disconnected');
            });
        });

        server.listen(this.PORT, () => {
            console.log(`Sensor listening on port ${this.PORT}`);
        });
    }
    async handleSensorMessage(socket,message){
        switch (message.type){
            case 'M1GS':
                this.processM1GSMessage(socket,message.content);
                break;
            case 'M3GS':
                this.processM3GSMessage(socket, message.content);
                break;
            default :
                console.log(`Unknown message type: ${message.type}`);
        }
    }

    async handleClientMessage(socket, message) {
        
        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'M1AS':
                this.processM1ASMessage(socket, message.content);
                break;
            case 'M3AS':
                this.processM3ASMessage(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }

    async processM3GSMessage(socket,content){

        console.log(`Processing M3GS message: ${content}\n\n`);

        const parts = content.split(" ");
        const Nonce = parts[0];
        const SK = parts[1];
        const PIog = parts[2];
        const T = Math.abs(Date.now()-Nonce);
        if(T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");

            const client = new MongoClient(uri)
            await client.connect();
            const database = client.db("database2");
            const collection2 = database.collection(collectionName);
            const collection1 = database.collection("collection1");
            const result = await collection2.find({ clientID: this.ID}).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const PI = pseudoIdentities[0];
            const result2 = await collection1.find({pseudoIdentity : PI}).toArray();
            const GSs = result2.map(entry => entry.gatewaySecret);
            const GS = GSs[0];
            const sessionKey = this.xorNumberWithString(SK,GS);
            // console.log(sessionKey,SK);
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
            console.log("Psuedo Identity has been updated from ",PI," to ",PInew,"\n\n");
            console.log("Session Key has also been generated : ",sessionKey,"(Session Key)");
        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }

    async processM1GSMessage(socket,content){

        console.log(`Processing M1AS message: ${content}\n\n`);

        const parts = content.split(" ");
        const Nonce = parts[0];
        // const gamma = parts [1];
        const neta = parts [parts.length-1];
        const T = Math.abs(Date.now() - Nonce);
        if(T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");

            const client = new MongoClient(uri)
            await client.connect();
            const database = client.db("database2");
            const collection2 = database.collection(collectionName);
            const collection1 = database.collection("collection1");
            const result = await collection2.find({ clientID: this.ID}).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const PI = pseudoIdentities[0];
            const psi= neta;
            const result2 = await collection1.find({pseudoIdentity : PI}).toArray();
            const GSs = result2.map(entry => entry.gatewaySecret);
            const tHashs = result2.map(entry => entry.tHash);
            const CAs = result2.map(entry => entry.CA);
            const GS = GSs[0];
            const tHash = tHashs[0];
            const CA = CAs[0];

            let gammaS = "";
            for (let i = 1; i < parts.length - 2; i++) {
                gammaS += parts[i] + " ";
            }
            gammaS += parts[parts.length - 2];
            const gamma = this.convertNumbersStringToByteArray(gammaS);
            const secretBytes = [];
                for (let i = 0; i < GS.length; i += 2) {
                    const byte = parseInt(GS.substr(i, 2), 16);
                    secretBytes.push(byte);
                }
                
                // Perform XOR operation between corresponding elements of response and gatewaySecret
            const challenge = gamma.map((num, index) => num ^ secretBytes[index]);
            const response = this.generateResponse(challenge);
            const pssi = this.hash(GS+response);
            // console.log("Values for psi",GS,response);
            // neta = BigInt(neta);
            if(psi === neta){
                console.log("Authentication of gateway at ISN Suceesful !, psi == neta with psi = ",psi,"and neta =",neta ,"\n\n");
            }
            else{
                console.log("Authentication of Gateway at ISN Unsuccessful , psi : ",psi,"\nneta :",neta,"\n\n")
            }
            const secretBytes1 = [];
            for (let i = 0; i < GS.length; i += 2) {
                const byte = parseInt(GS.substr(i, 2), 16);
                secretBytes1.push(byte);
            }
            // Perform XOR operation between corresponding elements of response and gatewaySecret
            const op_1 = response.map((num, index) => num ^ secretBytes1[index]);
            const op1 = op_1.join(' ');
            const op_2 = this.xorStrings(GS,this.ID);
            const message_8 = Date.now() + " " + op1 + " " + op_2 + " " + tHash + " " + CA;
            const responseMessage = {
                type : 'M2GS',
                content : message_8
            }
            this.sendMessage(socket,responseMessage);
            }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
   
    processM1ASMessage(socket, content) {
        // Process Type1 message content
       console.log(`Processing M1AS message: ${content}\n\n`);
        
       const challenge = this.convertNumbersStringToByteArray(content);
       const response = this.generateResponse(challenge);
       const ans = response.join(' ');
       const Ru = response.toString();
       const message_1 = this.ID+" "+ans;
        // PUF Challenge
        const responseMessage = {
            type: 'M2AS',
            content: message_1
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
    }

    async processM3ASMessage(socket, content) {
        // Process Type3 message content
        console.log(`Processing M3AS message: ${content}`,"\n\n");

        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        console.log('M4UA Message -',"\n\n");
        console.log("Transaction Hash :",this.TH2);
        console.log("Contract Address : ",this.CA);
        console.log("Psuedo Identity : ",this.PI);
        console.log("Gateway Secret : ",this.GS,"\n\n");
        socket.end();
    }
    
    hash(message) {
        const hash = crypto1.SHA256(message);
        return BigInt('0x' + hash.toString(crypto1.enc.Hex));
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
    xorNumberWithString(number, str) {
        // Convert string to an array of code points
        const codePoints = Array.from(str, char => char.charCodeAt(0));
    
        // Perform XOR operation between the number and each code point
        const xorResult = codePoints.map(codePoint => number ^ codePoint);
    
        // Convert the resulting array of code points back to a string
        const resultString = String.fromCharCode(...xorResult);
    
        return resultString;
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
    
    generatePseudoIdentity() {
        const pseudoIdentity = crypto.randomBytes(16).toString('hex');
        return pseudoIdentity;
    }

    // Function to generate a gateway secret
    generateGatewaySecret() {
        const gatewaySecret = crypto.randomBytes(32).toString('hex');
        return gatewaySecret;
    }
    
    sendMessage(socket, message) {
        // Send the message object to the Client
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message ${message.type} : ${JSON.stringify(message)}\n\n`);
    }
    generateChallenge() {
        // In a real PUF system, the challenge would be obtained from the hardware
        const challenge = crypto.randomBytes(16); // Adjust the size as needed
        return Array.from(challenge);
    }
}

// Create an instance of the Administrator
const sensor = new Sensor();
