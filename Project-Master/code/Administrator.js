const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")
const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';
const dbName = 'database1';
const collectionName = 'collection1';



class FuzzyExtractor {
    constructor(length, hamErr, repErr) {
        this.length = length;
        this.secLen = 2;
        this.numHelpers = this.calculateNumHelpers(hamErr, repErr);
        this.hashFunc = "sha256";
        this.nonceLen = 16;

        // // Generate seed for synchronizing random number generation
        // this.seed = crypto.randomBytes(32);

        // // Override random number generation function
        // crypto.randomBytes = (size) => {
        // return this.synchronizedRandomBytes(size, this.seed);
        // };
    }

    // // Function to override random number generation
    // synchronizedRandomBytes(size, seed) {
    // const hmac = crypto.createHmac('sha256', seed);
    // return hmac.update(Buffer.from(size.toString())).digest();
    // }

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
                // Recreate hmac for next iteration
                hmac = crypto.createHmac(hashFunc, salt);
            }

            return result;
        } catch (error) {
            console.error("Error in pbkdf2Hmac:", error);
            throw new Error("Error in pbkdf2Hmac");
        }
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
        this.PORT = [1024, 2000];
        this.ID = "";
        this.SNID = "";
        this.PI = "";
        this.PIsn = "";
        this.initializeServer();
        this.time = "";
        this.challenge = "";
        this.response = "";
        this.alpha = "";
        this.gatewaySecret = "";
        this.GSsn = "";
        this.socket = "";
        this.keyForAES = "";
        this.stime = "";
        this.etime="";
        this.keyForSN = "";
        this.newPI = "";
        this.oldPI = "";
    }


    //Function to connect to Sensor node during authentication
    connectToPort(responseMessage, port) {
        const socket2000 = new net.Socket();
        const ipAddress = '10.13.3.202';
        socket2000.connect(port, ipAddress, async () => {
            if (port === 2000) {
                console.log('Connected to Sensor\n');
            }
            else {
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

    //Initializing Admin for user registration or authentication
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
            console.log(`\nServer listening on port ${this.PORT[0]} \n`);
        });
    }

    //Handling client messages during reg./auth. of client
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
                this.processM3UGMessage(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    //Handling client messages during auth. of sensor
    async handleSensorMessage(socket, message) {

        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'Msync':
                this.processMsyncMessage(socket, message.content);
                break;
            case 'M2GS':
                this.processM2GSMessage(socket, message.content);
                break;

            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    async processMsyncMessage(socket,content){

        console.log(`Processing Msync message from Client : ${content}`, "\n\n");
        const parts = content.split(" ");
        const Nonce = parts[0];
        const PISNtoComp = parts[1];
         const T = Math.abs(Date.now()-Nonce);
         
         if (T <= 10000) {

             console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n");
             const client = new MongoClient(uri);
             await client.connect();
             const database = client.db("database2");
             const database4 = client.db("database4");
             const collection42 = database4.collection("collection2");
             const collection44 = database4.collection("collection4");
             const collection = database.collection(collectionName);
             const collection22 = database.collection("collection2");
             const collection23 = database.collection("collection3");
             
             const query = {
                $or: [
                    { pseudoIdentity: PISNtoComp },
                    { psuedoIDold: PISNtoComp }
                ]
            };
    
            // Perform the query
             const resultForPI = await collection23.findOne(query);
             const newPI = resultForPI ? resultForPI.pseudoIdentity : null;
             const oldPI = resultForPI ? resultForPI.psuedoIDold : null;
             const resultkey = await collection44.find({ pseudoIdentity: newPI }).toArray();
             const keyolds = resultkey.map(entry => entry.keyold);
             const keyold = keyolds[0];

            //Synchronisation Check
             if (oldPI === PISNtoComp) {
                 const filter = { pseudoIdentity: newPI };

                 const updateDocument = {
                     $set: {
                         pseudoIdentity: oldPI
                     }
                 };
                 const updateDocument1 = {
                     $set: {
                         key: keyold
                     }
                 };

                 const updateDocumentForPIold = {
                     $set: {
                         psuedoIDold: ""
                     }
                 };
                 const updateDocumentForKeyold = {
                     $set: {
                         keyold: ""
                     }
                 };
                 //Updating key for both sensor and user -
                 await Promise.all([

                     collection.updateOne(filter, updateDocument),
                     collection22.updateOne(filter, updateDocument),
                     collection23.updateOne(filter, updateDocumentForPIold),
                     collection22.updateOne(filter, updateDocument),

                 ]);

                 await Promise.all([

                     collection23.updateOne(filter, updateDocument),
                     collection42.updateOne(filter, updateDocument1),
                     
                     collection44.updateOne(filter, updateDocument1),
                     collection44.updateOne(filter, updateDocumentForKeyold),


                 ]);
                 await Promise.all([
                    collection42.updateOne(filter, updateDocument),
                     collection44.updateOne(filter, updateDocument),
                 ]);

             }


             const database2 = client.db("database2");

             const collection1 = database2.collection("collection1");
             const collection2 = database2.collection("collection2");
             const result2 = await collection2.find({ clientID: this.SNID }).toArray();

             const PISNs = result2.map(entry => entry.pseudoIdentity);
             const PISN = PISNs[0];
             this.PIsn = PISN;
             const result1 = await collection1.find({ pseudoIdentity: PISN }).toArray();
             const result42 = await collection42.find({ pseudoIdentity: PISN }).toArray();
             const keys = result42.map(entry => entry.key);
             this.keyForSN = keys[0];
             

             const challenges = result1.map(entry => entry.challenge);
             const responses = result1.map(entry => entry.response);
             const gsecrets = result1.map(entry => entry.gatewaySecret);
             const ChaSN = challenges[0];
             const ResSN = responses[0];
             const GSsn = gsecrets[0];
             this.GSsn = GSsn;

             // Perform XOR operation between corresponding elements of response and gatewaySecret
             const secretBytes = [];
             for (let i = 0; i < GSsn.length; i += 2) {
                 const byte = parseInt(GSsn.substr(i, 2), 16);
                 secretBytes.push(byte);
             }


             const gamma = ChaSN.map((num, index) => num ^ secretBytes[index]);

             
            const secretBytes1 = [];
            const PIForXOR = this.PIsn
             
             for (let i = 0; i < PIForXOR.length; i += 2) {
                 const byte = parseInt(PIForXOR.substr(i, 2), 16);
                 secretBytes1.push(byte);
             }

             // Perform XOR operation between corresponding elements of response and gatewaySecret
             const gammaXOR = gamma.map((num, index) => num ^ secretBytes1[index]);
             const temp = gammaXOR.join(" ");


             const startTime1 = performance.now();

             let neta = this.hash(GSsn + ResSN);

            //  neta = this.xorBigIntWith256BitString(neta, this.keyForSN);
            neta = this.xorBigIntWithString(neta, this.PIsn);

             const endTime1 = performance.now();
             const executionTime1 = endTime1 - startTime1;

             console.log("Execution Time of Hash Function:", executionTime1, "milliseconds");

             const m1gs = Date.now() + " " + temp + " " + neta;

             const responseMessage = {
                type : 'M1GS',
                content: m1gs
             }
             this.sendMessage(socket,responseMessage);

        }
        else {
            console.log("ERROR : The Received Message is not FRESH..........");
        }

    }


    async processM2GSMessage(socket, content) {

        console.log(`Processing M2GS message from Client : ${content}`, "\n\n");

        const parts = content.split(" ");
        const Nonce = parts[0];
        const tHash = parts[parts.length - 2];
        const CA = parts[parts.length - 1];
        const op2 = parts[parts.length - 3];

        let op1S = "";
        for (let i = 2; i < parts.length - 4; i++) {
            op1S += parts[i] + " ";
        }
        op1S += parts[parts.length - 4];
        const op1 = this.convertNumbersStringToByteArray(op1S);

        const T = Math.abs(Date.now() - Nonce);

        if (T <= 10000) {

            console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n");

            // Perform XOR operation between corresponding elements of response and gatewaySecret
            const GSsn = this.GSsn;
            const PIforXor = this.PIsn;
            const stime = performance.now();
            const op2Xor = this.xorStrings(op2,this.PIsn);
            const SNIOT = this.xorStrings(op2Xor, GSsn);
            const etime = performance.now();
            const exectime = etime-stime;
            console.log("Execution time of XOR function(Administrator):",exectime),"\n";

            const secretBytes1 = [];
            for (let i = 0; i < PIforXor.length; i += 2) {
                const byte = parseInt(PIforXor.substr(i, 2), 16);
                secretBytes1.push(byte);
            }
            
            let respnotXOR = op1.map((num, index) => num ^ secretBytes1[index]);

            const secretBytes = [];
            for (let i = 0; i < GSsn.length; i += 2) {
                const byte = parseInt(GSsn.substr(i, 2), 16);
                secretBytes.push(byte);
            }
            
            let respnot = respnotXOR.map((num, index) => num ^ secretBytes[index]);

            


            const client = new MongoClient(uri)
            await client.connect();
            const database2 = client.db("database2");
            const collection22 = database2.collection("collection2");
            const collection21 = database2.collection("collection1");
            const result22 = await collection22.find({ clientID: this.SNID }).toArray();
            const pIDs = result22.map(entry => entry.pseudoIdentity);
            const result2 = await collection21.find({ pseudoIdentity: pIDs[0] }).toArray();
            const responses = result2.map(entry => entry.response);
            const response = responses[0];
            const tHashComps = result2.map(entry => entry.tHash);
            const tHashComp = tHashComps[0];
            


            if (tHashComp === tHash){
                console.log("\nTransaction Hash is valid, (DOS attack check)\n");

                ////////////////////Blockchain////////////////////////

                //Fetching data from the deployed contract on blockchain with Contract address 'CA'-

                const IoTContract = await ethers.getContractAt('Sensor', CA);
                const gteway = await IoTContract.g();
                
                const gateway = this.hash(SNIOT + response);
                let g = await IoTContract.g()
                g = BigInt(g);
                
                //Authenticty of Sensor node is checked from the data fetched from blockchain -
                if (g == BigInt(gteway)) {
                    console.log("Authentication of Blockchain Data is successful!");


                    //Generating Session Key (SK) -
                    const buffer1 = crypto.randomBytes(16);
                    // Convert buffer to hexadecimal string
                    const hexStr1 = buffer1.toString('hex');
                    const sessionKey = hexStr1;

                    console.log("\nSession Key - ", sessionKey, "\n\n");


                    // Computing SK* to be sent to user -
                    const SKu = this.xorStrings(sessionKey, this.gatewaySecret);

                    // Computing SK# to be sent to sensor -
                    const SKsn = this.xorStrings(sessionKey, this.GSsn);

                    // Computing PIu2** to be sent to user -
                    const PIu2 = this.xorStrings(this.gatewaySecret, this.generatePseudoIdentity());

                    // Computing PIsn2# to be sent to sensor -
                    const PIsn2 = this.xorStrings(this.GSsn, this.generatePseudoIdentity());



                    const database4 = client.db("database4");
                    const collection41 = database4.collection("collection1");
                    const collection42 = database4.collection("collection2");
                    const collection43 = database4.collection("collection3");
                    const collection44 = database4.collection("collection4");


                    const database = client.db("database1");
                    const collection11 = database.collection("collection1");
                    const collection12 = database.collection("collection2");
                    const collection13 = database.collection("collection3");
                    



                    // Generating new key for user to be used in next authentication phase -

                    const buffer = crypto.randomBytes(32);
                    // Convert buffer to hexadecimal string
                    const hexStr = buffer.toString('hex');
                    console.log("key",this.keyForAES);
                    let keyForAEStest = this.xorStrings(this.keyForAES, hexStr);
                    const keyForAESnew = keyForAEStest.slice(0, 32);


                    const database2 = client.db("database2");
                    const collection21 = database2.collection("collection1");
                    const collection22 = database2.collection("collection2");
                    const collection23 = database2.collection("collection3");


                    // Generating new key for sensor node to be used in next authentication phase -
                    const buffer2 = crypto.randomBytes(32);
                    // Convert buffer to hexadecimal string
                    const hexStr2 = buffer2.toString('hex');
                    let keyForAEStest2 = this.xorStrings(this.keyForSN, hexStr2);
                    const keyForAESnewSN = keyForAEStest2.slice(0, 32);


                    //Updating key and psuedo identities of user and sensor node to be used in next authentication phase -
                    const filter = { pseudoIdentity: this.PI };
                    const filter1 = { pseudoIdentity: this.PIsn };
                    const updateDocumentKey = {
                        $set: {
                            key: keyForAESnew
                        }
                    };
                    const updateDocumentKeySN = {
                        $set: {
                            key: keyForAESnewSN
                        }
                    };


                    //Updating key for both sensor and user -
                    await Promise.all([
                        collection42.updateOne(filter1, updateDocumentKeySN),
                        collection41.updateOne(filter, updateDocumentKey),

                    ]);
                    const updateDocument = {
                        $set: {
                            pseudoIdentity: this.xorStrings(this.gatewaySecret, PIu2)
                        }
                    };
                    const updateDocumentPI = {
                        $set: {
                            psuedoIDold: this.PI
                        }
                    };
                    const updateDocumentPISN = {
                        $set: {
                            psuedoIDold: this.PIsn
                        }
                    };
                    const updateDocumentkeyold = {
                        $set: {
                            keyold: this.keyForAES
                        }
                    };
                    const updateDocumentkeyoldSN = {
                        $set: {
                            keyold: this.keyForSN
                        }
                    };
                    const updateDocument1 = {
                        $set: {
                            pseudoIdentity: this.xorStrings(this.GSsn, PIsn2)
                        }
                    };

                    //Updating psuedo identities for both user and sensor -
                    await Promise.all([
                        collection11.updateOne(filter, updateDocument),
                        collection12.updateOne(filter, updateDocument),
                        collection41.updateOne(filter, updateDocument),
                        collection21.updateOne(filter1, updateDocument1),
                        collection42.updateOne(filter1, updateDocument1),
                        collection22.updateOne(filter1, updateDocument1)
                    ]);

                    await Promise.all([

                        collection13.updateOne(filter, updateDocumentPI),
                        
                    ]);
                    await Promise.all([
                        collection13.updateOne(filter, updateDocument),
                        
                    ]);
                    await Promise.all([
                        collection43.updateOne(filter, updateDocumentKey),
                        collection43.updateOne(filter, updateDocumentkeyold),
                    ]);
                    await Promise.all([ 
                        collection43.updateOne(filter, updateDocument),
                    ]);
                    await Promise.all([
                        collection23.updateOne(filter1, updateDocumentPISN),
                    ]);
                    await Promise.all([
                        collection23.updateOne(filter1, updateDocument1),
                    ]);
                    await Promise.all([
                        collection44.updateOne(filter1, updateDocumentKeySN),
                        collection44.updateOne(filter1, updateDocumentkeyoldSN),
                    ]);
                    await Promise.all([
                        collection44.updateOne(filter1, updateDocument1),
                    ]);



                    let m4ugBeforeEncryption = Date.now() + " " + SKu + " " + PIu2 + " " + this.hash(this.xorStrings(this.gatewaySecret, this.PI)) + " " + hexStr;

                    //Encrypting the message to be sent to the user for session key generation -
                    const startTime = performance.now();
                    let m4ug = this.encryptAES(m4ugBeforeEncryption, this.keyForAES);
                    const endTime = performance.now();
                    const executionTime = endTime - startTime;
                    console.log("Execution Time for Encryption:", executionTime, "milliseconds");


                    const m3gsBeforeEncryption = Date.now() + " " + SKsn + " " + PIsn2 + " " + this.hash(this.xorStrings(this.GSsn, this.PIsn)) + " " + hexStr2;
                    let m3gs = this.encryptAES(m3gsBeforeEncryption, this.keyForSN);


                    const responseMessageU = {
                        type: "M4UG",
                        content: m4ug
                    }
                    const responseMessageSN = {
                        type: "M3GS",
                        content: m3gs
                    }
                    this.sendMessage(socket, responseMessageSN);
                    this.sendMessage(this.socket, responseMessageU);
                }
                else {
                    console.log("Authentication of Blockchain Data is unsuccessful \n\n");
                }
                
            }
            else{
                console.log("Transaction Hash is invalid");   
                console.log(tHash,"!=",tHashComp);
            }

        }
        else {
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }

    async processM3UGMessage(socket, content) {

        console.log(`Processing M3UG message from Client : ${content}`, "\n\n");

        //Extracting data received from M3UG message from client
        const parts = content.split(" ");
        const timestamp = parseInt(parts[0]);
        const delta = parts[1];

        let muS = "";
        for (let i = 2; i < parts.length - 4; i++) {
            muS += parts[i] + " ";
        }
        muS += parts[parts.length - 4];
        const mu = this.convertNumbersStringToByteArray(muS);

        const SNIDxor = parts[parts.length - 3];
        this.SNID = this.xorStrings(SNIDxor,this.PI);
        const tHash = parts[parts.length - 2];
        const CA = parts[parts.length - 1];


        const T = Math.abs(timestamp - Date.now());

        if (T <= 10000) {
            console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n\n");
            let deltaxor = this.xorStrings(delta,this.PI);
            let midhash = this.xorStrings(deltaxor, this.gatewaySecret);
            midhash = BigInt(midhash);
            
            // Perform XOR operation between corresponding elements of response and gatewaySecret
            const GSXOR = this.gatewaySecret;
            const PIXOR = this.PI;
            const secretBytes2 = [];
            for (let i = 0; i < PIXOR.length; i += 2) {
                const byte = parseInt(PIXOR.substr(i, 2), 16);
                secretBytes2.push(byte);
            }

            
            const muxor = mu.map((num, index) => num ^ secretBytes2[index]);

            const secretBytes1 = [];
            for (let i = 0; i < GSXOR.length; i += 2) {
                const byte = parseInt(GSXOR.substr(i, 2), 16);
                secretBytes1.push(byte);
            }

            
            const response = muxor.map((num, index) => num ^ secretBytes1[index]);
            const res = Buffer.from(response);
            
            const Gateway = midhash + this.hash(res);

            const client = new MongoClient(uri)
            await client.connect();
            
            const database1 = client.db("database1");
            const collection12 = database1.collection("collection2");
            const result12 = await collection12.find({ pseudoIdentity: this.PI }).toArray();
            const tHashComps = result12.map(entry => entry.tHash);
            const tHashComp = tHashComps[0];


            //Validating the transaction hash recieved from client to avoid DOS attack
            if (tHashComp === tHash){
                console.log("Transaction Hash is valid, (DOS attack check)\n");


                //////////////////////Blockchain////////////////////////

                //Fetching user data which is deployed on blockchain with contract address 'CA' -

                const IoTContract = await ethers.getContractAt('IoT', CA);
               
                // Extract alpha and t from eventData
                const alpha = await IoTContract.alpha()
                const t = await IoTContract.t()
                const alphat = BigInt(alpha) + BigInt(t);
                
                // const gateway = BigInt(mdhash.toString() + this.hash(res));
                // const bigInt = BigInt(alphat.toString());
                const database4 = client.db("database4");
                const collection42 = database4.collection("collection2");
                const result42 = await collection42.find({ pseudoIdentity: this.PIsn }).toArray();
                const keys = result42.map(entry => entry.key);
                this.keyForSN = keys[0];


                //Validating authenticity of user from blockchain
                if (Gateway === alphat) {
                    console.log("Authentication of User and Device using Blockchain data is Successful \n\n");

                    const flag = 1;
                    const msync = Date.now() + " " + flag ;

                    const responseMessage = {
                        type: "MsyncCheck",
                        content: msync
                    }
                    this.socket = socket;
                    this.connectToPort(responseMessage, 2000);
                }
                else {
                    console.log("Authentication Of User and Device is unsuccessful at Blockchain\n\n");
                }

            }
            else{
                console.log("Transaction Hash is not valid");
                console.log(tHash, " != " ,tHashComp);
            }
            
        }
        else {
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
    async processM1UGMessage(socket, content) {

        console.log(`Processing M1UG message from Client : ${content}`, "\n\n");

        const parts = content.split(' ');
        const mode = parts[0];
        this.PI = parts[1];
        const PItoComp = parts[1];
        const timestamp = parseInt(parts[2]);

        const T = Math.abs(timestamp - Date.now());
        let m2ug = "";

        const client = new MongoClient(uri);

        if (T <= 10000) {
            console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n\n");
            

            try {
                // Connect to the MongoDB cluster to fetch user contents from database for authentication phase

                
                await client.connect();
                const database = client.db(dbName);
                const database4 = client.db("database4");
                const collection41 = database4.collection(collectionName);
                const collection43 = database4.collection("collection3");
                const collection = database.collection(collectionName);
                const collection12 = database.collection("collection2");
                const collection13 = database.collection("collection3");
                // const resultForPI = await collection13.find({ clientID : cID}).toArray();
                const query = {
                    $or: [
                        { pseudoIdentity: PItoComp },
                        { psuedoIDold: PItoComp }
                    ]
                };
        
                // Perform the query
                const resultForPI = await collection13.findOne(query);
                const newPI = resultForPI ? resultForPI.pseudoIdentity : null;
                const oldPI = resultForPI ? resultForPI.psuedoIDold : null;
                
            
                const resultkey = await collection43.find({ pseudoIdentity: newPI }).toArray();
                const keyolds = resultkey.map(entry => entry.keyold);
                const keyold = keyolds[0];

                //Synchronisation Check
                if(oldPI === PItoComp){
                    const filter = { pseudoIdentity: newPI };
                    
                    const updateDocument = {
                        $set: {
                            pseudoIdentity:oldPI
                        }
                    };
                    const updateDocument1 = {
                        $set: {
                            key:keyold
                        }
                    };

                    const updateDocumentForPIold = {
                        $set: {
                            psuedoIDold:""
                        }
                    };
                    const updateDocumentForKeyold = {
                        $set: {
                            keyold:""
                        }
                    };
                    //Updating key for both sensor and user -
                    await Promise.all([
                        
                        collection.updateOne(filter, updateDocument),
                        collection12.updateOne(filter, updateDocument),
                        collection13.updateOne(filter, updateDocumentForPIold),
                        collection12.updateOne(filter, updateDocument),
                        
                    ]);
                    
                    await Promise.all([

                        collection13.updateOne(filter, updateDocument),
                        collection41.updateOne(filter, updateDocument1),
                        
                        collection43.updateOne(filter, updateDocument1),
                        collection43.updateOne(filter, updateDocumentForKeyold),
   
   
                    ]);
                    await Promise.all([
                       collection41.updateOne(filter, updateDocument),
                        collection43.updateOne(filter, updateDocument),
                    ]);

                }
                

                const pI = this.PI;
                const result = await collection.find({ pseudoIdentity: pI }).toArray();
                const resultForKey = await collection41.find({ pseudoIdentity: pI }).toArray();
                const keys = resultForKey.map(entry => entry.key);
                
                
                //Fetching key from database
                this.keyForAES = keys[0];
               

                const challenges = result.map(entry => entry.challenge);
                const responses = result.map(entry => entry.response);
                const gsecrets = result.map(entry => entry.gatewaySecret);
                const challenge = challenges[0]; const response = responses[0]; const gatewaySecret = gsecrets[0];

                const secretBytes = [];
                for (let i = 0; i < gatewaySecret.length; i += 2) {
                    const byte = parseInt(gatewaySecret.substr(i, 2), 16);
                    secretBytes.push(byte);
                }

                // Perform XOR operation between corresponding elements of challenge and gatewaySecret to compute 'beta' 
                let  beta = challenge.map((num, index) => num ^ secretBytes[index]);
               
                
                const secretBytes1 = [];
                const PIforXOR = this.PI;
                for (let i = 0; i < PIforXOR.length; i += 2) {
                    const byte = parseInt(PIforXOR.substr(i, 2), 16);
                    secretBytes1.push(byte);
                }
                let betaXOR = beta.map((num, index) => num ^ secretBytes1[index]);
                betaXOR = betaXOR.join(" ");


                const concatenation = gatewaySecret + response;
                let j = this.hash(concatenation);
                j = this.xorBigIntWithString(j,PIforXOR);
                
                m2ug = Date.now() + " " + betaXOR + " " + j;
                this.gatewaySecret = gatewaySecret;
            } catch (e) {
                console.error('Error:', e);
            } finally {
                // Close the client connection
                await client.close();
            }

        }
        else {
            console.log("ERROR : The Received Message is not FRESH..........");
        }
        const responseMessage = {
            type: 'M2UG',
            content: m2ug
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);

    }

    processM1UAMessage(socket, content) {

        console.log(`Processing M1UA message from Client : ${content}`, "\n\n");
        //User message recieved with request and ID
        const parts = content.split(' ');
        const mode = parts[0];
        this.ID = parts[1];

        // Prepare Challenge
        this.challenge = this.generateChallenge();
        const message_2 = this.challenge.join(' ');

        //Send Challenge to User 
        const responseMessage = {
            type: 'M2UA',
            content: message_2
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
    }

    async processM3UAMessage(socket, content) {

        // Process Type3 message content
        console.log(`Processing M3UA message from Client : ${content}`, "\n\n");
        
        const Message_3 = content.split(' ');


        //Alpha and Ru recieved from User -

        this.alpha = Message_3[0];

        for (let i = 1; i < Message_3.length - 1; i++) {
            this.response += Message_3[i] + " ";
        }

        this.response += Message_3[Message_3.length - 1];
        const resp = this.convertNumbersStringToByteArray(this.response);

        
        //Generating Key during registration phase of user -

        const uint8Array = new Uint8Array(resp);
        const res = Buffer.from(uint8Array);
        const buffer = crypto.randomBytes(32);
        // Convert buffer to hexadecimal string
        const hexString = buffer.toString('hex');
        let keyForAEStest = this.xorStrings(this.bufferTo256BitString(res), hexString);
        const keyForAES = keyForAEStest.slice(0, 32);
        

        //Compute t
        const t = this.hash(res);

        

        // Check if contract has been deployed for the first user(Modification1) -

        const client = new MongoClient(uri);
        await client.connect();
        const db1 = client.db("database3");

        // Access the collection
        const collection1 = db1.collection("collection1");

        // Check if collection is empty
        const count = await collection1.countDocuments({});
        let contract, cA;
        if (count === 0) {
            const IoTContract = await ethers.getContractFactory("IoT");
            const deployer = (await ethers.getSigners())[0];
            contract = await IoTContract.deploy();
            await contract.deployed();
            cA = contract.address;
            const dataToInsert = {
                cAddress: cA,
            };
            const result = await collection1.insertOne(dataToInsert);
        }
        else {
            const document = await collection1.findOne({}, { projection: { _id: 0, cAddress: 1 } });

            contract = await ethers.getContractAt("IoT", document.cAddress);
        }
        client.close();


        //Add user and device data in blockchain -

        const alpha1 = ethers.BigNumber.from(this.alpha);
        const t1 = ethers.BigNumber.from(t);
        const tx = await contract.addUnD(alpha1, t1);

        // Wait for transaction receipt
        const receipt = await tx.wait();


        //Computing Transaction Hash and Contract Address From the Deployed User Reg. Contract
        const TH2 = receipt.transactionHash;
        const CA = contract.address;

        console.log('Transaction Hash:', TH2);
        console.log('Contract Address:', CA, "\n\n");


        //Generate Pseudo Identity and Gateway Secret
        const PI = this.generatePseudoIdentity();
        const GS = this.generateGatewaySecret();
        
        
       

        //Store in database Pseudo Identity,challenge,response,gatewaySecret 
        const dataToInsert = {
            pseudoIdentity: PI,
            challenge: this.challenge,
            response: res,
            gatewaySecret: GS
        };
        //Store in database Pseudo Identity,Client ID, Gateway Secret, Transaction Hash, Contract Address
        const dataToInsert2 = {
            pseudoIdentity: PI,
            clientID: this.ID,
            gatewaySecret: GS,
            tHash: TH2,
            cAddress: CA
        };
        
        const dataToInsertPI = {
            pseudoIdentity: PI,
            psuedoIDold: "",
        };
        //Store in database Key for Encryption and Pseudo Identity
        const dataToInsert3 = {
            key: keyForAES,
            pseudoIdentity: PI,
        }
        const dataToInsertKey = {
            key: keyForAES,
            keyold:"",
            pseudoIdentity: PI,
        }
        const client1 = new MongoClient(uri);
        await client1.connect();
       
        // Specify the database
        const db = client1.db(dbName);
        const db4 = client1.db("database4");
        // Specify the collection
        const collection = db.collection('collection1');
        const collection2 = db.collection('collection2');
        const collection3 = db.collection('collection3');
        const collection1new = db4.collection('collection1');
        const collection1Key = db4.collection('collection3');

        // Insert documents into the collection
        try {
            const result = await collection.insertOne(dataToInsert);
            const result2 = await collection2.insertOne(dataToInsert2);
            const result5 = await collection3.insertOne(dataToInsertPI);
            const result3 = await collection1new.insertOne(dataToInsert3);
            const result4 = await collection1Key.insertOne(dataToInsertKey);

            // Fetch data from the collection
            const docs = await collection.find({}).toArray();
            const docs1 = await collection2.find({}).toArray();
        } catch (error) {
            console.error('Error inserting data or fetching data from collection:', error);
        } finally {
            // Close the connection
            client1.close();
        }

        const M4UA = TH2 + " " + CA + " " + PI + " " + GS + " " + keyForAES;

        const responseMessage = {
            type: 'M4UA',
            content: M4UA
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
    base64ToByteArray(base64) {
        var binaryString = atob(base64);
        var byteArray = new Uint8Array(binaryString.length);
        for (var i = 0; i < binaryString.length; i++) {
            byteArray[i] = binaryString.charCodeAt(i);
        }
        return byteArray;
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
    
    xorBytesWith256BitString(byteArray, bit256String) {
        // Convert 256-bit string to an array of bytes (code points)
        const stringBytes = Array.from(bit256String, char => char.charCodeAt(0));

        // Perform XOR operation on each pair of bytes
        const xorResult = byteArray.map((byte, index) => byte ^ stringBytes[index] || 0);

        return xorResult;
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

    bufferTo256BitString(buffer) {
        // Convert buffer to hexadecimal string
        const hexString = buffer.toString('hex');

        // Extract first 256 bits (32 bytes) from hexadecimal string
        const bit256String = hexString.slice(0, 64);

        return bit256String;
    }
    // Function to encrypt plaintext using AES
    encryptAES(plaintext, key) {
        const iv = crypto.randomBytes(16); // Generate random initialization vector
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { iv: iv.toString('hex'), encryptedData: encrypted };
    }
}

// Create an instance of the Administrator
const administrator = new Administrator();