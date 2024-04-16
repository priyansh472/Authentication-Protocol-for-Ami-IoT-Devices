const net = require('net');
const crypto = require('crypto');
const crypto1 = require('crypto-js');
const { ethers, run, network } = require("hardhat")
const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';

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
class Administrator {
    constructor() {
        this.PORT = 1000;
        this.ID = "";
        this.mode = "";
        this.challenge="";
        this.response="";
        this.CA = "";
        this.TH3 = "";
        this.TH4="";
        this.initializeAdministrator();
    }

    initializeAdministrator() {
        const ipAddress = '127.0.0.1';
        const socket = new net.Socket();

        socket.connect(this.PORT, ipAddress, () => {
            console.log('Admin Listening in registration mode -',"\n\n");
            this.mode = "Registration";
            this.challenge = this.generateChallenge();
            const message_1 = this.challenge.join(' ');
            // Send Type1 message to the Administrator
            const message1 = {
                type: 'M1AS',
                content: message_1
            };
            this.sendMessage(socket, message1);
        });

        socket.on('data', (data) => {
            const receivedMessage = JSON.parse(data.toString());
            this.handleSensorMessage(socket, receivedMessage);
        });

        socket.on('end', () => {
            console.log('Connection closed');
        });
    }
    
    async handleSensorMessage(socket, message) {
        console.log(`Received message from Sensor : ${JSON.stringify(message)}\n\n`);

        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'M2AS':
                this.processM2ASMessage(socket, message.content);
                break;
            case 'M3AS':
                this.processM3ASMessage(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    
    async processM2ASMessage(socket, content) {
        // Process Type2 message content
        console.log(`Processing M2AS message: ${content} \n\n`);

        const Message_2 = content.split(' '); 
        this.ID = Message_2[0];

        for(let i=1;i<Message_2.length-1;i++){
            this.response += Message_2[i] + " ";
        }

        this.response += Message_2[Message_2.length-1];
        const resp = this.convertNumbersStringToByteArray(this.response);
        const uint8Array = new Uint8Array(resp);
        const res = Buffer.from(uint8Array);
        const g = this.hash(this.ID+this.response);
        const g1 = ethers.BigNumber.from(g);

        //////////Blockchain Network///////////
        const SensorContract = await ethers.getContractFactory("Sensor");
        const lock= await SensorContract.deploy()
        const txReceipt = await lock.deployTransaction.wait();
        this.TH3 = txReceipt.transactionHash;
        const blockNumber = txReceipt.blockNumber;
        const contractCreator = txReceipt.from;
        this.CA= lock.address;
        const transactionFee = ethers.utils.formatEther(txReceipt.gasUsed.mul(lock.deployTransaction.gasPrice));
        const gasUsed = txReceipt.gasUsed.toString();
        
        const [deployer] = await ethers.getSigners();
        const contract = await ethers.getContractAt('Sensor', this.CA, deployer);

     
        const gString = g.toString();
        const tx = await contract.addUnD(g1);
        const receipt = await tx.wait();
        this.TH4 = receipt.transactionHash;

        console.log('Transaction Hash:', this.TH4,"\n\n");
        console.log('Contract Address:', this.CA,"\n\n");

        const PI = this.generatePseudoIdentity();
        const GS = this.generateGatewaySecret();
        const Message_3 = this.TH4+" "+this.CA+" "+PI+" "+GS;

        // Send Type3 message to the Administrator
        const message3 = {
            type: 'M3AS',
            content: Message_3
        };

        const client = new MongoClient(uri);
        const dataToInsert = {
            pseudoIdentity: PI,
            challenge: this.challenge,
            response: res,
            gatewaySecret: GS,
            tHash: this.TH4,
            CA : this.CA 
        };
        const dataToInsert2 = {
            pseudoIdentity: PI,
            clientID : this.ID
        };
        // Connect to MongoDB server
        await client.connect(async function(err) {
            console.log(err)
        })

        // Specify the database
        const db = client.db("database2");

        // Specify the collection
        const collection1 = db.collection('collection1');
        const collection2 = db.collection('collection2');

        // Insert documents into the collection
        try {
            const result = await collection1.insertOne(dataToInsert);
            const result2 = await collection2.insertOne(dataToInsert2);

        } catch (error) {
            console.error('Error inserting data or fetching data from collection:', error);
        } finally {
            // Close the connection
            client.close();
        }
        this.sendMessage(socket, message3);
    }

    processM3ASMessage(socket, content) {
        // Process Type4 message content
        console.log(`Processing M3AS message: ${content}\n\n`);
        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        console.log('M4UA');
        console.log(this.TH2);
        console.log(this.CA);
        console.log(this.PI);
        console.log(this.GS);
        // Close the connection
        socket.end();
    }

    sendMessage(socket, message) {
        // Send the message object to the Sensor
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message ${message.type} to Sensor: ${JSON.stringify(message)}\n\n`);
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
        // In a real PUF system, the response would be generated based on the unique physical characteristics
        // For simulation purposes, we'll use a cryptographic hash function (SHA-256) as an example
        try {
            const crypto = require('crypto');
            const digest = crypto.createHash('sha256');
            return Buffer.from(digest.update(Buffer.from(challenge)).digest());
        } catch (error) {
            console.error(error);
            return null;
        }
    }
    generateChallenge() {
        // In a real PUF system, the challenge would be obtained from the hardware
        const challenge = crypto.randomBytes(16); // Adjust the size as needed
        return Array.from(challenge);
    }
    hash(message) {
        const hash = crypto1.SHA256(message);
        return BigInt('0x' + hash.toString(crypto1.enc.Hex));
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

// Create an instance of the Client
const administrator = new Administrator();

