const net = require('net');
const crypto = require('crypto');
const crypto1 = require('crypto-js');
const bigInt = require('big-integer');
const { MongoClient } = require('mongodb');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat");
const { exec } = require('child_process');
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
                
                hmac = crypto.createHmac(hashFunc, salt);
            }

            return result;
        } catch (error) {
            console.error("Error in pbkdf2Hmac:", error);
            throw new Error("Error in pbkdf2Hmac");
        }
    }
}


class Client {
    constructor() {
        this.PORT = 1024;
        this.ID = "";
        this.SNID = "";
        this.time = "";
        this.mode = "";
        this.TH2 = "";
        this.CA = "";
        this.PI = "";
        this.GS = "";
        this.Helper = "";
        this.keyForAES = "";
        this.challenge = "";
        this.res = "";
        this.startTime = "";
        this.endTime = "";
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

    async getData() {

    }

    async initializeClient() {

        // const ipAddress = '10.61.5.62';
        const ipAddress = '10.13.3.128';
        const socket = new net.Socket();
        const ques = "\nDo you want to register(1) or authenticate(2): ";
        const input = await this.getInput(ques);
        socket.connect(this.PORT, ipAddress, async () => {
            console.log('\nConnected to server');
            if (input === '1') {
                this.startTime=performance.now();
                this.mode = "Registration";
                const ques1 = "\nPlease provide your User ID : ";
                const input1 = await this.getInput(ques1);
                this.ID = input1;
                const M1 = this.mode + " " + this.ID + " " + Date.now();
                const message1 = {
                    type: 'M1UA',
                    content: M1
                };
                this.sendMessage(socket, message1);

            }
            else {
                this.startTime = performance.now();
                this.mode = "\nAuthentication";
                const ques1 = "\nPlease provide your User ID : ";
                const input1 = await this.getInput(ques1);
                this.ID = input1;
                const ques2 = "\nPlease provide the ID of the Sensor node to which you want to connect : ";
                const input2 = await this.getInput(ques2);
                this.SNID = input2;
                const client = new MongoClient(uri);

                try {
                    // Connect to the MongoDB cluster
                    await client.connect();
                    // Access a specific database
                    const database = client.db(dbName);

                    // Access a specific collection and fetch the Psuedo Identity associated with the specific User -
                    const collection = database.collection(collectionName);
                    const pI = this.ID;
                    const result = await collection.find({ clientID: pI }).toArray();
                    const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
                    this.PI = pseudoIdentities[0];


                } catch (e) {
                    console.error('Error:', e);
                } finally {
                    // Close the client connection
                    await client.close();
                }
                const Nonce = Date.now();
                
                const M1UG = this.mode + " " + this.PI + " " + Nonce ;
                const m1ug = {
                    type: 'M1UG',
                    content: M1UG
                };
                this.sendMessage(socket, m1ug);
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
                this.processM4UGMessage(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }

    async processM4UGMessage(socket, content) {

        console.log("\nMessage M4UG starts being processed here");
        console.log(`\nProcessing M4UG message: ${content}`, "\n\n");

        //Decrypting the message received from the Gateway -
        const stime = performance.now();
        const cipher = this.decryptAES(content.encryptedData,this.keyForAES,content.iv);
        const etime = performance.now();
        const exectime = etime-stime;
        console.log("Decryption time:",exectime);
        const parts = cipher.split(" ");
        const Nonce = parts[0];
        
        const PIog = parts[2];
        const hashToComp = parts[3];
        const hexStr = parts[4];
        
        const T = Math.abs(Nonce - Date.now());

        if (T <= 10000) {

            console.log("\nThe Received message is within the defined clock skew T [ms] = " + T, "\n\n");


            //Fetching the details of the User from the database -
            const client = new MongoClient(uri)
            await client.connect();
            const database4 = client.db("database4");
            const collection41 = database4.collection("collection1");
            const database = client.db("database1");
            const collection2 = database.collection("collection2");
            const collection1 = database.collection("collection1");
            const result = await collection2.find({ clientID: this.ID }).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const PI = pseudoIdentities[0];
            const result2 = await collection1.find({ pseudoIdentity: PI }).toArray();
            const GSs = result2.map(entry => entry.gatewaySecret);
            const GS = GSs[0];
            const ress = result2.map(entry => entry.response);
            const res = ress[0];

            let Hash = this.hash(this.xorStrings(GS,PI));

            if (Hash == hashToComp){
                console.log("Authenticity and Integrity check Successfull, (Hash from Gateway and from User database match successfully)\n");
            }
            else{
                console.log("Auth. and Int. check unsuccessful");
                console.log(Hash, " != ", hashToComp);
            }

            //Session Key is derived by doing XOR of SK* and gateway secret
            const sessionKey = this.xorStrings(parts[1], GS);

            //Pseudo Identity is derived by doing XOR of PIu2* and gateway secret
            const stime = performance.now();
            const PInew = this.xorStrings(PIog, GS);
            const etime = performance.now();
            const exectime = etime-stime;
            console.log("Execution Time for XOR : ",exectime," milliseconds\n");
            const filter = { pseudoIdentity: PI };

            //Generating Key to be used in next authentication phase -
            let newKeytest = this.xorStrings(this.keyForAES,hexStr);
            const newKey = newKeytest.slice(0,32);
            
            //Pseudo Identity gets updated.
            const updateDocument = {
                $set: {
                    pseudoIdentity: PInew
                }
            };

            //The new key which is to be updated in the database 
            const updateDocument1 = {
                $set: {
                    key: newKey
                }
            };

            //Here the Psuedo Identitites gets updated where it is mapped to key and the User Data
            await Promise.all([
                collection2.updateOne(filter, updateDocument),
                collection1.updateOne(filter, updateDocument),
                collection41.updateOne(filter, updateDocument1),
            ]);
            //The key gets updated in the database
            await Promise.all([
                collection41.updateOne(filter, updateDocument),
            ]);


            console.log("Psuedo Identity has been updated from : ", PI, " to : ", PInew, "\n\n");
            console.log("Session Key has also been generated : ", sessionKey, "(Session Key)");
            this.endTime = performance.now();
            const executionTime = this.endTime-this.startTime;
            console.log("\nMessage M4UG finishes being processed here");
            console.log("\nExecution time of authentication:",executionTime,"milliseconds");
        }
        else {
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
    async processM2UAMessage(socket, content) {

        console.log("\nMessage M2UA starts being processed here");
        console.log(`\nProcessing M2UA message: ${content}`, "\n\n");

        const challenge = this.convertNumbersStringToByteArray(content);
        const response = this.generateResponse(challenge);

        this.challenge = challenge;
        this.res = response;
        const ans = response.join(' ');

        const fuzzyExtractor = new FuzzyExtractor(32, 0.01, 0.01);
        const { key, publicHelper } = fuzzyExtractor.generate(response);

        //Using Biometric S1 and S2 are generated.
        const keyAndHelper = fuzzyExtractor.generate(response);
        const S1 = Buffer.from(keyAndHelper.key).toString('utf-8');

        const client = new MongoClient(uri);
        await client.connect();
        const dataToInsert = {
           clientID: this.ID,
           Biometric: S1
        };
       
        //Connect to MongoDB server
        const db = client.db("database10");
        const collection1 = db.collection('collection1');

        try {
        const result = await collection1.insertOne(dataToInsert);

        const docs = await collection1.find({}).toArray();

        } catch (error) {
        console.error('Error inserting data or fetching data from collection:', error);
        } finally {
        // Close the connection
        client.close();
        }

        const startTime = performance.now();
        const alpha = this.hash(S1 + this.ID);
        
        const endTime = performance.now();
        const executionTime = endTime - startTime;

        console.log('Execution time of Hash function:', executionTime, 'milliseconds');
        
        const Ru = response.toString();
        const M3UA = alpha + " " + ans;

        // Send M3UA message to the Administrator
        const m3ua = {
            type: 'M3UA',
            content: M3UA
        };
        console.log("\nMessage M2UA finishes being processed here");
        this.sendMessage(socket, m3ua);
    }

    async processM4UAMessage(socket, content) {

        // Process M4UA message content
        console.log("\nMessage M4UA starts being processed here");
        console.log(`\nProcessing Type4 message: ${content}`, "\n\n");

        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        this.keyForAES = parts[4];

        console.log('M4UA contents : ', "\n");
        console.log("Transaction Hash : ", this.TH2);
        console.log("Contract Address : ", this.CA);
        console.log("Psuedo Identity :", this.PI);
        console.log("Gateway Secret :", this.GS, "\n");
        console.log("KeyForAES :", this.keyForAES, "\n");

        //The challenege and the response pair gets stored in the database in collection1
        const dataToInsert = {
            pseudoIdentity: this.PI,
            challenge: this.challenge,
            response: this.res,
            gatewaySecret: this.GS
        };
        //TH2,CA,PI,GS gets stored in the database
        const dataToInsert2 = {
            pseudoIdentity: this.PI,
            clientID: this.ID,
            gatewaySecret: this.GS,
            tHash: this.TH2,
            cAddress: this.CA
        };

        //Key gets stored in database
        const dataToInsert3 = {
            key: this.keyForAES,
            pseudoIdentity: this.PI,
        }

        // Connect to MongoDB server
        const client = new MongoClient(uri);
        await client.connect();

        // Specify the database
        const db = client.db(dbName);
        const db4 = client.db("database4");
        // Specify the collection
        const collection = db.collection('collection1');
        const collection2 = db.collection('collection2');
        const collection1new = db4.collection('collection1');

        // Insert documents into the collection
        try {
            const result = await collection.insertOne(dataToInsert);
            const result2 = await collection2.insertOne(dataToInsert2);
            const result3 = await collection1new.insertOne(dataToInsert3);

            // Fetch data from the collection
            const docs = await collection.find({}).toArray();
            const docs1 = await collection2.find({}).toArray();
        } catch (error) {
            console.error('Error inserting data or fetching data from collection:', error);
        } finally {
            // Close the connection
            client.close();
        }
        // Close the connection
        this.endTime = performance.now();
        const executionTime = this.endTime-this.startTime;
        console.log("\nMessage M4UA finishes being processed here");
        console.log("\nExecution time of registration : ",executionTime," milliseconds");
        socket.end();
    }

    async processM2UGMessage(socket, content) {

        console.log("\nMessage M2UG startes being processed here");
        console.log(`\nProcessing M2UG message from Administrator: ${content}`, "\n\n");
        const client = new MongoClient(uri);

        let parts = content.split(" ");
        let j = parts[parts.length - 1];
        j = BigInt(j);
        let Nonce = parts[0];
        let M3UG = "";
        const cID = this.ID;

        try {

            // Connect to the MongoDB cluster
            await client.connect();
            const database = client.db(dbName);
            const database10 = client.db("database10");
            const collection101 = database10.collection("collection1");
            const result10 = await collection101.find({ clientID: cID }).toArray();
            const Biometrics = result10.map(entry => entry.Biometric);
            const Biometric = Biometrics[0];
            const database4 = client.db("database4");

            // Access a specific collection
            const collection2 = database.collection(collectionName);
            const collection41 = database4.collection("collection1");

            //Fetching the tHash , CA , PI and the key from the database - 
            const result = await collection2.find({ clientID: cID }).toArray();
            const pseudoIdentities = result.map(entry => entry.pseudoIdentity);
            const gsecrets = result.map(entry => entry.gatewaySecret);
            const tHash1 = result.map(entry => entry.tHash);
            const cAddress1 = result.map(entry => entry.cAddress);
            this.PI = pseudoIdentities[0];
            const resultnew = await collection41.find({ pseudoIdentity: this.PI }).toArray();
            const keys = resultnew.map(entry => entry.key);
            this.keyForAES = keys[0];
            
            j = this.xorBigIntWithString(j,this.PI);
            
            let gatewaySecret = gsecrets[0];
            let tHash = tHash1[0];
            let cAddress = cAddress1[0];

            const fuzzyExtractor1 = new FuzzyExtractor(32, 0.01, 0.01);

            const T = Math.abs(Date.now() - Nonce);

            if (T <= 10000) {

                console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n");

                // Converting the beta(in string format) into Byte Array -
                let betaS = "";
                for (let i = 1; i < parts.length - 2; i++) {
                    betaS += parts[i] + " ";
                }
                betaS += parts[parts.length - 2];
                const betaXOR = this.convertNumbersStringToByteArray(betaS);

                //Performing the XOR operation between beta and key to prevent the traceability attack -
                const PIXOR = this.PI;
                const secretBytes1 = [];
                for (let i = 0; i < PIXOR.length; i += 2) {
                    const byte = parseInt(PIXOR.substr(i, 2), 16);
                    secretBytes1.push(byte);
                }
                const beta = betaXOR.map((num, index) => num ^ secretBytes1[index]);


                // Challenge gets generated by doing XOR of Gateway Secret and Beta
                const secretBytes = [];
                for (let i = 0; i < gatewaySecret.length; i += 2) {
                    const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                    secretBytes.push(byte);
                }
                const challenge = beta.map((num, index) => num ^ secretBytes[index]);

                // Response gets generated at user end
                const response = this.generateResponse(challenge);

                const { key, publicHelper } = fuzzyExtractor1.generate(response);

                // Omega gets generated by doing hash of the concatenation of gateway secret and response
                const omega = this.hash(gatewaySecret + response);
                j = BigInt(j)

                // Validating if omega is equal to j or not.
                if (omega === j) {

                    console.log("Authentication successful(AS) of Gateway at User Device !, 'omega == j' ,where omega = ", omega, "and j = ", j, "\n\n");

                    const fuzzyExtractor = new FuzzyExtractor(32, 0.01, 0.01);
                    // Useing Biometric and S2 reproducing S1.
                    const Sb = fuzzyExtractor.reproduce(response, publicHelper);
                    const S1 = Sb.toString('hex');

                    //Computing hash of S1 and User ID
                    const midhash = this.hash(Biometric + this.ID);
                    
                    //Computing delta by doing XOR of hash generated and gateway secret
                    let delta = this.xorStrings(midhash.toString(), gatewaySecret);
                    delta = this.xorStrings(delta,PIXOR);


                    // Computing XOR of Gateway secret and response to obtain mu -
                    const secretBytes1 = [];
                    for (let i = 0; i < gatewaySecret.length; i += 2) {
                        const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                        secretBytes1.push(byte);
                    }
                    const muXOR = response.map((num, index) => num ^ secretBytes1[index]);

                    const secretBytes2 = [];
                    for (let i = 0; i < PIXOR.length; i += 2) {
                        const byte = parseInt(PIXOR.substr(i, 2), 16);
                        secretBytes2.push(byte);
                    }
                    const mu = muXOR.map((num, index) => num ^ secretBytes2[index]);
                    const SNID = this.xorStrings(this.SNID,this.PI);


                    const m5 = mu.join(' ');

                    M3UG = Date.now() + " " + delta + " " + m5 + " " + SNID + " " + tHash + " " + cAddress;
                    console.log("Message M2UG finishes being processed here");
                }
                else{
                    console.log("Authentication unsuccessful of Gateway at User Device !, 'omega != j' ,where omega = ", omega, "and j = ", j, "\n\n");
                }

            }
            else {
                console.log("ERROR : The Received Message is not FRESH..........");
            }

        } catch (e) {
            console.error('Error:', e);
        } finally {
            const m3ug = {
                type: 'M3UG',
                content: M3UG
            }
            this.sendMessage(socket, m3ug);
            // Close the client connection
            await client.close();
        }

    }

    sendMessage(socket, message) {
        // Send the message object to the Administrator
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message ${message.type} to Administrator: ${JSON.stringify(message)}`, "\n\n");
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
    bufferTo256BitString(buffer) {
        // Convert buffer to hexadecimal string
        const hexString = buffer.toString('hex');

        // Extract first 256 bits (32 bytes) from hexadecimal string
        const bit256String = hexString.slice(0, 64);

        return bit256String;
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

    xorStringWith256BitString(string, bitString) {
        // Convert the string to a byte array
        const stringBytes = Buffer.from(string);

        // Convert the 256-bit string to a byte array
        const bitStringBytes = Buffer.from(bitString, 'hex');

        // Ensure both arrays are of the same length
        const maxLength = Math.max(stringBytes.length, bitStringBytes.length);
        const paddedStringBytes = Buffer.alloc(maxLength);
        const paddedBitStringBytes = Buffer.alloc(maxLength);
        stringBytes.copy(paddedStringBytes, maxLength - stringBytes.length);
        bitStringBytes.copy(paddedBitStringBytes, maxLength - bitStringBytes.length);

        // Perform XOR operation element-wise
        const resultBytes = Buffer.alloc(maxLength);
        for (let i = 0; i < maxLength; i++) {
            resultBytes[i] = paddedStringBytes[i] ^ paddedBitStringBytes[i];
        }

        // Convert the result byte array back to a string
        const resultString = resultBytes.toString('hex');

        return resultString;
    }

    xorBigIntWith256BitString(bigIntNumber, bit256String) {
        // Convert BigInt number to binary string
        let binaryBigInt = bigIntNumber.toString(2);

        // Pad the binary string with leading zeros to ensure it's 256 bits long
        while (binaryBigInt.length < 256) {
            binaryBigInt = '0' + binaryBigInt;
        }

        // Convert the 256-bit string to its binary representation
        let binaryString = '';
        for (let i = 0; i < bit256String.length; i++) {
            const charCode = bit256String.charCodeAt(i);
            const binaryChar = charCode.toString(2).padStart(8, '0');
            binaryString += binaryChar;
        }

        // Perform XOR operation bit by bit
        let xorResult = '';
        for (let i = 0; i < binaryBigInt.length; i++) {
            xorResult += binaryBigInt[i] ^ binaryString[i];
        }
        
        // Convert the XOR result back to a BigInt
        const xorBigInt = BigInt('0b' + xorResult);

        return xorBigInt;
    }
    xorBigIntWithString(bigIntNumber, bit256String) {
        // Convert BigInt number to binary string
        let binaryBigInt = bigIntNumber.toString(2);

        // Pad the binary string with leading zeros to ensure it's 256 bits long
        while (binaryBigInt.length < bit256String.length) {
            binaryBigInt = '0' + binaryBigInt;
        }

        // Convert the 256-bit string to its binary representation
        let binaryString = '';
        for (let i = 0; i < bit256String.length; i++) {
            const charCode = bit256String.charCodeAt(i);
            const binaryChar = charCode.toString(2).padStart(8, '0');
            binaryString += binaryChar;
        }

        // Perform XOR operation bit by bit
        let xorResult = '';
        for (let i = 0; i < binaryBigInt.length; i++) {
            xorResult += binaryBigInt[i] ^ binaryString[i];
        }
        
        // Convert the XOR result back to a BigInt
        const xorBigInt = BigInt('0b' + xorResult);

        return xorBigInt;
    }

    decryptAES(ciphertext, key, iv) {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv, 'hex'));
        let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

}

// Create an instance of the Client
const client = new Client();