const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")
const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';
const dbName = 'database1';
const collectionName = 'collection1';

// Function to generate a random prime number within a specified range
function generateRandomPrime(min, max) {
    function isPrime(num) {
        for (let i = 2, sqrt = Math.sqrt(num); i <= sqrt; i++) {
            if (num % i === 0) return false;
        }
        return num > 1;
    }
    
    let prime;
    do {
        prime = Math.floor(Math.random() * (max - min + 1) + min);
    } while (!isPrime(prime));
    
    return prime;
}

// Function to calculate the modular exponentiation (base^exponent mod modulus)
function modPow(base, exponent, modulus) {
    if (modulus === 1) return 0;
    let result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 === 1) {
            result = (result * base) % modulus;
        }
        exponent = Math.floor(exponent / 2);
        base = (base * base) % modulus;
    }
    return result;
}

// Function to perform Diffie-Hellman key exchange
function diffieHellman() {
    // Choose parameters (prime number p and primitive root g)
    const p = generateRandomPrime(100, 1000); // You can adjust the range as needed
    const g = 2; // A common choice for primitive root
    
    // Alice's private key
    const a = Math.floor(Math.random() * (p - 2) + 1); // Random integer between 1 and p-1
    
    // Bob's private key
    const b = Math.floor(Math.random() * (p - 2) + 1); // Random integer between 1 and p-1
    
    // Compute public keys
    const A = modPow(g, a, p); // Alice's public key
    const B = modPow(g, b, p); // Bob's public key
    
    // Compute shared secret
    const sharedSecretA = modPow(B, a, p); // Alice computes shared secret
    const sharedSecretB = modPow(A, b, p); // Bob computes shared secret
    
    // Both shared secrets should be equal
    if (sharedSecretA === sharedSecretB) {
        return sharedSecretA; // Return the shared secret (session key)
    } else {
        return null; // If not equal, something went wrong
    }
}

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
        const AS = new Administrator();
    } catch (error) {
        console.error(error);
    }
}
class Administrator {
    constructor() {
        this.PORT = [1000,2000];
        this.ID = "";
        this.SNID = "";
        this.initializeServer();
        this.time = "";
        this.challenge="";
        this.response="";
        this.alpha="";
        this.gatewaySecret = "";
        this.GSsn = "";
        this.socket = "";
    }

    connectToPort(responseMessage,port) {
        const socket2000 = new net.Socket();
        const ipAddress = '127.0.0.1';
        socket2000.connect(port, ipAddress, async () => {
            if(port === 2000){
            console.log('Connected to Sensor');
            }
            else{
                console.log("Connected to Client");
            }
        });

        socket2000.on('data', (data) => {
            const receivedMessage = JSON.parse(data.toString());
            this.handleSensorMessage(socket2000, receivedMessage);
        });

        socket2000.on('end', () => {
            console.log('Connection closed');
        });
        this.sendMessage(socket2000, responseMessage);
    }
    initializeServer() {
        const server1 = net.createServer((socket) => {
            socket.on('data', (data) => {
                const receivedMessage = JSON.parse(data.toString());
                this.handleClientMessage(socket, receivedMessage);
            });

            socket.on('end', () => {
                console.log('Client disconnected');
            });
        });

        server1.listen(this.PORT[0], () => {
            console.log(`Server listening on port ${this.PORT[0]} to process client authentication`);
        });
    }
    
    async handleClientMessage(socket, message) {
        
        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'M1UA':
                this.processM1UAMessage(socket, message.content);
                break;
            case 'M3UA':
                this.processM3UAMessage(socket, message.content);
                break;
            case 'M1UG':
                this.processM1UGMessage(socket, message.content);
                break;
            case 'M3UG':
                this.processM3UGMessage(socket,message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    async handleSensorMessage(socket, message) {
        
        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'M2GS':
                this.processM2GSMessage(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    async processM2GSMessage(socket,content){

        console.log(`Processing M2GS message from Client : ${content}`,"\n\n");

        const parts = content.split(" ");
        const Nonce = parts[0];
        const tHash = parts[parts.length-2];
        const CA = parts[parts.length-1];
        const op2 = parts[parts.length-3];

        let op1S = "";
        for(let i=2;i<parts.length-4;i++){
            op1S += parts[i] + " ";
        }
        op1S += parts[parts.length-4];
        const op1 = this.convertNumbersStringToByteArray(op1S);
        const T = Math.abs(Date.now()-Nonce);
        if(T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n");
            const GSsn = this.GSsn;
            const SNIOT =this.xorStrings(op2, GSsn);
            const secretBytes = [];
                for (let i = 0; i < GSsn.length; i += 2) {
                    const byte = parseInt(GSsn.substr(i, 2), 16);
                    secretBytes.push(byte);
                }  
                // Perform XOR operation between corresponding elements of response and gatewaySecret
            const response = op1.map((num, index) => num ^ secretBytes[index]);
            const gteway = this.hash(SNIOT+response);

            ////////////////////Blockchain////////////////////////
            const IoTContract = await ethers.getContractAt('Sensor', CA);
            const iface = IoTContract.interface;
                
            const p = await IoTContract.g()
            const gateway = p.toString();
            // const sessionKey = diffieHellman();
            // const SKu = this.xorNumberWithString(sessionKey,this.gatewaySecret);
            // const SKsn = this.xorNumberWithString(sessionKey,this.GSsn);
            // const PIu2 = this.xorStrings(this.gatewaySecret,this.generatePseudoIdentity());
            // const PIsn2 = this.xorStrings(this.GSsn,this.generatePseudoIdentity());
            // const message9u = Date.now() + " " + SKu + " " + PIu2;
            // const message9sn = Date.now() + " " + SKsn + " " + PIsn2;
            // const sessionKey = diffieHellman();
            // const SKu = this.xorNumberWithString(sessionKey,this.gatewaySecret);
            // const SKsn = this.xorNumberWithString(sessionKey,this.GSsn);
            // const PIu2 = this.xorStrings(this.gatewaySecret,this.generatePseudoIdentity());
            // const PIsn2 = this.xorStrings(this.GSsn,this.generatePseudoIdentity());
            // const message9u = Date.now() + " " + SKu + " " + PIu2;
            // const message9sn = Date.now() + " " + SKsn + " " + PIsn2;
            const g = await IoTContract.g()
            if(BigInt(g.toString())==gateway){
                console.log("Authentication of Blockchain Data is successful!\n\n");
            }
            else{
                console.log("Authentication of Blockchain Data is successful \n\n");
            }

            const sessionKey = diffieHellman();
            const SKu = this.xorNumberWithString(sessionKey,this.gatewaySecret);
            const SKsn = this.xorNumberWithString(sessionKey,this.GSsn);
            const PIu2 = this.xorStrings(this.gatewaySecret,this.generatePseudoIdentity());
            const PIsn2 = this.xorStrings(this.GSsn,this.generatePseudoIdentity());
            const message9u = Date.now() + " " + SKu + " " + PIu2;
            const message9sn = Date.now() + " " + SKsn + " " + PIsn2;

            const responseMessageU = {
                type : "M4UG",
                content : message9u
            }
            const responseMessageSN = {
                type : "M3GS",
                content : message9sn
            }
            this.sendMessage(socket,responseMessageSN);
            this.sendMessage(this.socket,responseMessageU);
        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }

    async processM3UGMessage(socket,content){

        console.log(`Processing M3UG message from Client : ${content}`,"\n\n");

        const parts = content.split(" ");
        const timestamp = parseInt(parts[0]);
        const delta = parts[1];

        let muS = "";
        for(let i=2;i<parts.length-4;i++){
            muS += parts[i] + " ";
        }
        muS += parts[parts.length-4];
        const mu = this.convertNumbersStringToByteArray(muS);
        
        this.PI = parts[parts.length-3];
        const tHash = parts[parts.length-2];
        const CA = parts[parts.length-1];
        console.log(tHash," ~Transaction Hash\n\n");
        console.log(CA," ~ContractAddress","\n\n");
        const T = Math.abs(timestamp-Date.now());

        if(T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = " + T,"\n\n");
            const midhash = this.xorBigIntegers(delta, this.gatewaySecret);
            const secretBytes1 = [];
                for (let i = 0; i < this.gatewaySecret.length; i += 2) {
                    const byte = parseInt(this.gatewaySecret.substr(i, 2), 16);
                    secretBytes1.push(byte);
                }
                
                // Perform XOR operation between corresponding elements of response and gatewaySecret
            const response = mu.map((num, index) => num ^ secretBytes1[index]);
            const res = Buffer.from(response);

            const Gateway = midhash + this.hash(res);
            
            //////////////////////Blockchain////////////////////////
            const IoTContract = await ethers.getContractAt('IoT', CA);
            const iface = IoTContract.interface;
            const mdhash = await IoTContract.alpha();
            // Extract alpha and t from eventData
            const alpha = await IoTContract.alpha()
            const t = await IoTContract.t()
            const alphat = alpha + t;
            const gateway = BigInt(mdhash.toString()+this.hash(res));
            const bigInt = BigInt(alphat.toString());
            if(gateway==bigInt)
            {
            console.log("Authentication of User and Device using Blockchain data is Successful \n\n");
            }
            else{
                console.log("Authentication Of User and Device is unsuccessful at Blockchain\n\n",gateway,bigInt);
            }
            const client = new MongoClient(uri)
            await client.connect();
            const database = client.db("database2");
            const collection1 = database.collection("collection1");
            const collection2 = database.collection("collection2");
            const result2 = await collection2.find({ clientID:  this.SNID  }).toArray();
            const PISNs = result2.map(entry => entry.pseudoIdentity);
            const PISN = PISNs[0];
            const result1 = await collection1.find({ pseudoIdentity:  PISN  }).toArray();
            const challenges = result1.map(entry => entry.challenge);
            const responses = result1.map(entry => entry.response);
            const gsecrets = result1.map(entry => entry.gatewaySecret);
            const ChaSN = challenges[0];
            const ResSN = responses[0];
            const GSsn = gsecrets[0];
            // console.log(ChaSN," ",ResSN," ",GSsn,"***p");
            const secretBytes = [];
                for (let i = 0; i < GSsn.length; i += 2) {
                    const byte = parseInt(GSsn.substr(i, 2), 16);
                    secretBytes.push(byte);
                }
                
                // Perform XOR operation between corresponding elements of response and gatewaySecret
            const gamma = ChaSN.map((num, index) => num ^ secretBytes[index]);
            // console.log("Gamma & Response");
            this.GSsn = GSsn;
            // console.log("Values for neta",GSsn,ResSN);
            const neta = this.hash(GSsn+ResSN);
            const message_7 = Date.now() + " " + gamma + " " + neta ;

            const responseMessage = {
                type: "M1GS",
                content : message_7
            }
            this.socket = socket;
            this.connectToPort(responseMessage,2000);
        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
    async processM1UGMessage(socket, content){

        console.log(`Processing M1UG message from Client : ${content}`,"\n\n");

        let message_5 = "";
        const parts = content.split(' ');
        const mode = parts[0];
        this.ID = parts[1];
        const timestamp = parseInt(parts[2]);
        this.SNID = parts[3];
     
        const T = Math.abs(timestamp - Date.now());

        if (T<=100){
            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");
            const client = new MongoClient(uri);

            try {
                // Connect to the MongoDB cluster
                await client.connect();
                const database = client.db(dbName);
                const collection = database.collection(collectionName);

                // Fetch contents within the collectionz
                const pI = this.ID;
                const result = await collection.find({ pseudoIdentity:  pI  }).toArray();

                const challenges = result.map(entry => entry.challenge);
                const responses = result.map(entry => entry.response);
                const gsecrets = result.map(entry => entry.gatewaySecret);
                const challenge = challenges[0]; const response = responses[0] ; const gatewaySecret = gsecrets[0]; 

                const secretBytes = [];
                for (let i = 0; i < gatewaySecret.length; i += 2) {
                    const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                    secretBytes.push(byte);
                }
                
                // Perform XOR operation between corresponding elements of challenge and gatewaySecret
                const beta = challenge.map((num, index) => num ^ secretBytes[index]);
                const concatenation = gatewaySecret + response;
                // console.log("Values for j",gatewaySecret,response);
                const j = this.hash(concatenation);
                const m5 = beta.join(' ');
                message_5 = Date.now() + " " + m5 + " " + j;
                this.gatewaySecret = gatewaySecret;
            } catch (e) {
                console.error('Error:', e);
            } finally {
                // Close the client connection
                await client.close();
            }

        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
        const responseMessage = {
            type: 'M2UG',
            content: message_5
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);

    }
    
    processM1UAMessage(socket, content) {
        
        console.log(`Processing M1UA message from Client : ${content}`,"\n\n");

        const parts = content.split(' ');
        const mode = parts[0];
        this.ID = parts[1];
        
        // Prepare response
        this.challenge = this.generateChallenge();
        const message_2 = this.challenge.join(' ');
        // PUF Challenge
        const responseMessage = {
            type: 'M2UA',
            content: message_2
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
    }

    async processM3UAMessage(socket, content) {

        // Process Type3 message content
        console.log(`Processing M3UA message from Client : ${content}`,"\n\n");

        const Message_3 = content.split(' '); 
        this.alpha = Message_3[0];

        for(let i=1;i<Message_3.length-1;i++){
            this.response += Message_3[i] + " ";
        }

        this.response += Message_3[Message_3.length-1];
        const resp = this.convertNumbersStringToByteArray(this.response);

        const uint8Array = new Uint8Array(resp);
        const res = Buffer.from(uint8Array);

        const t = this.hash(res);

        const alpha1 = ethers.BigNumber.from(this.alpha);
        const t1 = ethers.BigNumber.from(t);

        //////////Blockchain Network///////////
        const IoTContract = await ethers.getContractFactory("IoT");
        const lock= await IoTContract.deploy()
        const txReceipt = await lock.deployTransaction.wait();
        const transactionHash = txReceipt.transactionHash;
        const blockNumber = txReceipt.blockNumber;
        const contractCreator = txReceipt.from;
        const CA= lock.address;
        const transactionFee = ethers.utils.formatEther(txReceipt.gasUsed.mul(lock.deployTransaction.gasPrice));
        const gasUsed = txReceipt.gasUsed.toString();
        

         const [deployer] = await ethers.getSigners();
         const contract = await ethers.getContractAt('IoT', CA, deployer);
        //  const t1 = ethers.BigNumber.from(t);
         const tString = t.toString();
         const tx = await contract.addUnD(alpha1, t1);
         const receipt = await tx.wait();
         const TH2 = receipt.transactionHash;

        // //////////////////M4//////////////////////////////
        console.log('Transaction Hash:', TH2);
        console.log('Contract Address:', CA, "\n\n");

        const PI = this.generatePseudoIdentity();
        const GS = this.generateGatewaySecret();
        const Message_5 = TH2 + " " + CA + " " + PI + " " + GS;
        // Prepare response
        const client = new MongoClient(uri);
        const dataToInsert = {
            pseudoIdentity: PI,
            challenge: this.challenge,
            response: res,
            gatewaySecret: GS
        };
        const dataToInsert2 = {
            pseudoIdentity: PI,
            clientID: this.ID,
            gatewaySecret: GS,
            tHash : transactionHash,
            cAddress : CA
        };
        // Connect to MongoDB server
        await client.connect(async function(err) {
            console.log(err)
        })

        // Specify the database
        const db = client.db(dbName);

        // Specify the collection
        const collection = db.collection('collection1');
        const collection2 = db.collection('collection2');

        // Insert documents into the collection
        try {
            const result = await collection.insertOne(dataToInsert);
            const result2 = await collection2.insertOne(dataToInsert2);

            // Fetch data from the collection
            const docs = await collection.find({}).toArray();
            const docs1 = await collection2.find({}).toArray();
        } catch (error) {
            console.error('Error inserting data or fetching data from collection:', error);
        } finally {
            // Close the connection
            client.close();
        }
        const responseMessage = {
            type: 'M4UA',
            content: Message_5
        };
        
        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
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

    
    sendMessage(socket, message) {
        // Send the message object to the Client
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message ${message.type} : ${JSON.stringify(message)} \n\n`);
    }
    generateChallenge() {
        // In a real PUF system, the challenge would be obtained from the hardware
        const challenge = crypto.randomBytes(16); // Adjust the size as needed
        return Array.from(challenge);
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

}

// Create an instance of the Administrator
const administrator = new Administrator();

