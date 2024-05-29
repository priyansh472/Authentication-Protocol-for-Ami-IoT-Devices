const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const mysql = require('mysql');
const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';
const collectionName = 'collection2';

//Biometric Code
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
        this.PORT = 1024;
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
        this.keyForAES = "";
        this.startTime = "";
        this.endTime = "";
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
        //INPUT ASKING FOR REGISTRATION OR AUTHENTICATION
        const ques = "\nDo you want to register(1) or authenticate(2): ";
        const input = await this.getInput(ques);
        switch(input){
            case '1':
                this.startTime=performance.now();
                this.initializeServer();
                break;
            case '2':
                this.startTime=performance.now();
                this.initializeSensor();
                break;
            default:
                console.log(`Unknown message type: ${input}`);
        }

    }
    async initializeSensor(){
        const ques1 = "\nPlease provide the Sensor ID to be authenticated : ";
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
        const ques1 = "\nPlease provide the Sensor ID to be registered : ";
        const input = await this.getInput(ques1);
        this.ID = input;
        const server = net.createServer((socket) => {
            socket.on('data', (data) => {
                const receivedMessage = JSON.parse(data.toString());
                this.handleClientMessage(socket, receivedMessage);
            });

            socket.on('end', () => {
                console.log('Admin disconnected');
            });const connection = mysql.createConnection({
                host: 'localhost',
                user: 'root',
                password: 'security123',
                database: 'database1'
            });
    
        });

        server.listen(this.PORT, () => {
            console.log(`\nSensor listening on port ${this.PORT}\n`);
        });
    }
    async handleSensorMessage(socket,message){
        switch (message.type){
            case 'MsyncCheck':
                this.processMsyncCheckMessage(socket,message.content);
                break;
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
    async processMsyncCheckMessage(socket,content){

        console.log(`Processing MsyncCheck message: ${content}\n\n`);

        const parts = content.split(" ");
        const Nonce = parts[0];
        const flag = parts[1];
        const T = Math.abs(Date.now()-Nonce);

        if(T<=300){

            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");
            if(flag === '1'){

                let tHash, CA1, PI1, GS1;
                const connection = mysql.createConnection({
                    host: 'localhost',
                    user: 'root',
                    password: 'security123',
                    database: 'database1'
                });

                // Connect to the database
                await new Promise((resolve, reject) => {
                    connection.connect((err) => {
                        if (err) {
                            console.error('Error connecting to database: ' + err.stack);
                            reject(err);
                        } else {
                            resolve();
                        }
                    });
                });

                //Fetch details about Transaction Hash , Contract Address, Key which will be used in sending messages and encryption
                try {
                    const sensorIdToFetch = this.ID;
                    const sql = 'SELECT TH2, CA, PI, GS, keyForAES FROM collection1 WHERE sensor_id = ?';
                    const results = await new Promise((resolve, reject) => {
                        connection.query(sql, [sensorIdToFetch], (err, results) => {
                            if (err) {
                                console.error('Error fetching data: ' + err.stack);
                                reject(err);
                            } else {
                                resolve(results);
                            }
                        });
                    });

                    if (results.length > 0) {
                        const { TH2, CA, PI, GS, keyForAES } = results[0];
                        tHash = TH2;
                        CA1 = CA;
                        PI1 = PI;
                        GS1 = GS;
                        this.keyForAES = keyForAES;

                    } else {
                        console.log('No data found for sensor ID: ' + sensorIdToFetch);
                    }
                } catch (error) {
                    console.error('Error:', error);
                } finally {
                    // Close the connection
                    connection.end();
                }

                
                const msync = Date.now() + " " + PI1 ;
                const responseMessage = {
                    type : 'Msync',
                    content : msync
                }
                this.sendMessage(socket,responseMessage);
            }
            else{
                console.log("Gateway is not in synchronisation mode");
            }

        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }


    }
    async processM3GSMessage(socket,content){

        console.log(`Processing M3GS message: ${content}\n\n`);
        

        //Decrypting the cipher at sensor end using key
        let cipher = this.decryptAES(content.encryptedData,this.keyForAES,content.iv);

        const parts = cipher.split(" ");
        const Nonce = parts[0];
        const SK = parts[1];
        const PIog = parts[2];
        const hashToComp = parts[3];
        const hexStr = parts[4];
        const T = Math.abs(Date.now()-Nonce);
        
        if(T<=300){

            console.log("The Received message is within the defined clock skew T [ms] = "+T,"\n\n");

            let tHash, CA1, PI1, GS1;
            const connection = mysql.createConnection({
                host: 'localhost',
                user: 'root',
                password: 'security123',
                database: 'database1'
            });
            // Connect to the database
            await new Promise((resolve, reject) => {
                connection.connect((err) => {
                    if (err) {
                        console.error('Error connecting to database: ' + err.stack);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });

            //Corresponding to sensor id fetching its details stored during registration phase from database
            try {
                const sensorIdToFetch = this.ID;
                const sql = 'SELECT TH2, CA, PI, GS FROM collection1 WHERE sensor_id = ?';
                const results = await new Promise((resolve, reject) => {
                    connection.query(sql, [sensorIdToFetch], (err, results) => {
                        if (err) {
                            console.error('Error fetching data: ' + err.stack);
                            reject(err);
                        } else {
                            resolve(results);
                        }
                    });
                });

                if (results.length > 0) {
                    const { TH2, CA, PI, GS } = results[0];
                    tHash = TH2;
                    CA1 = CA;
                    PI1 = PI;
                    GS1 = GS;

                    let Hash = this.hash(this.xorStrings(GS1,PI1));
                    if(Hash === BigInt(hashToComp)){

                        console.log("\nAuth. and Int. check successful");

                        //Generating new key using xor of old key and nonce

                        let newkeytest = this.xorStrings(this.keyForAES, hexStr);
                        const newkey = newkeytest.slice(0, 32);

                        //Generating session key by doing xor of SK# and gateway secret
                        const sessionKey = this.xorStrings(SK, GS1);

                        //Generating new Pseudo Id by doing xor of PI# and gateway secret
                        const PInew = this.xorStrings(PIog, GS1);

                        
                        //Updating the Pseudo Id in sensor database
                        const sql1 = 'UPDATE collection1 SET PI = ? WHERE sensor_id = ?';

                        // Execute the query to update data
                        connection.query(sql1, [PInew, sensorIdToFetch], (err, results) => {
                            if (err) {
                                console.error('Error updating data: ' + err.stack);
                                return;
                            }

                            if (results.affectedRows > 0) {
                                console.log('\nSuccessfully updated PI for sensor ID: ' + PInew + ' \n');
                            } else {
                                console.log('No rows were updated.');
                            }
                        });
                        //Updating key for decryption at sensor node
                        const sql2 = 'UPDATE collection1 SET keyForAES = ? WHERE sensor_id = ?';

                        connection.query(sql2, [newkey, sensorIdToFetch], (err, results) => {
                            if (err) {
                                console.error('Error updating data: ' + err.stack);
                                return;
                            }

                            if (results.affectedRows > 0) {
                                console.log('\nSuccessfully updated Key for sensor ID: ' + newkey + '\n\n');
                            } else {
                                console.log('No rows were updated.');
                            }
                        });
                        console.log("\nPsuedo Identity has been updated from ", PI1, " to ", PInew, "\n\n");
                        console.log("Session Key has also been generated : ", sessionKey, "(Session Key)\n");

                    }
                    else {
                        console.log("Auth. and Int. check unsuccessful")
                        console.log(Hash, "!= ", hashToComp);
                    }
                    
                } else {
                    console.log('No data found for sensor ID: ' + sensorIdToFetch);
                }
                this.endTime = performance.now();
                const executionTime = this.endTime - this.startTime;
               // console.log("\n\nExecution time for authentication,", executionTime, "milliseconds\n");
            } catch (error) {
                console.error('Error:', error);
            } finally {
                // Close the connection
                connection.end();
            }


        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }

    async processM1GSMessage(socket,content){
        //Authentication Phase for sensor node begins 
        console.log(`\nProcessing M1GS message: ${content}\n\n`);

        const parts = content.split(" ");
        const Nonce = parts[0];
        
        let neta = parts [parts.length-1];

        const T = Math.abs(Date.now() - Nonce);

        if(T<=300){

            console.log("The Received message is within the defined clock skew T [ms] = " + T, "\n\n");
            let tHash, CA1, PI1, GS1;

            // Create a connection to the database
            const connection = mysql.createConnection({
                host: 'localhost',
                user: 'root',
                password: 'security123',
                database: 'database1'
            });

            // Connect to the database
            await new Promise((resolve, reject) => {
                connection.connect((err) => {
                    if (err) {
                        console.error('Error connecting to database: ' + err.stack);
                        reject(err);
                    } else {
                        console.log('Connected to database as id ' + connection.threadId);
                        resolve();
                    }
                });
            });

            //Fetch details about Transaction Hash , Contract Address, Key which will be used in sending messages and encryption
            try {
                const sensorIdToFetch = this.ID;
                const sql = 'SELECT TH2, CA, PI, GS, keyForAES FROM collection1 WHERE sensor_id = ?';
                const results = await new Promise((resolve, reject) => {
                    connection.query(sql, [sensorIdToFetch], (err, results) => {
                        if (err) {
                            console.error('Error fetching data: ' + err.stack);
                            reject(err);
                        } else {
                            resolve(results);
                        }
                    });
                });

                if (results.length > 0) {
                    const { TH2, CA, PI, GS, keyForAES } = results[0];
                    tHash = TH2;
                    CA1 = CA;
                    PI1 = PI;
                    GS1 = GS;
                    this.keyForAES = keyForAES;

                } else {
                    console.log('No data found for sensor ID: ' + sensorIdToFetch);
                }
            } catch (error) {
                console.error('Error:', error);
            } finally {
                // Close the connection
                connection.end();
            }

            //Performing XOR between(neta , gamma) and key to prevent traceability attack -
            neta = BigInt(neta);
            neta = this.xorBigIntWithString(neta, PI1);

            let gammaS = "";
            for (let i = 1; i < parts.length - 2; i++) {
                gammaS += parts[i] + " ";
            }
            gammaS += parts[parts.length - 2];
            const gammaXOR = this.convertNumbersStringToByteArray(gammaS);
            
            const PIForXOR = PI1;
        
            const secretBytes1 = [];
            for (let i = 0; i < PIForXOR.length; i += 2) {
                const byte = parseInt(PIForXOR.substr(i, 2), 16);
                secretBytes1.push(byte);
            }

            // Generate Challenge by doing XOR of gamma and gateway secret
            const gamma = gammaXOR.map((num, index) => num ^ secretBytes1[index]);
            
            const secretBytes = [];
            for (let i = 0; i < GS1.length; i += 2) {
                const byte = parseInt(GS1.substr(i, 2), 16);
                secretBytes.push(byte);
            }

            // Generate Challenge by doing XOR of gamma and gateway secret
            const challenge = gamma.map((num, index) => num ^ secretBytes[index]);

            //Compute Response at sensor end
            const response = this.generateResponse(challenge);
            this.response = response;

            //Computing PSI 
            const startTime = performance.now();
            const psi = this.hash(GS1 + response);
            const endTime = performance.now();
            const executionTime = endTime - startTime;
            console.log('\nExecution Time of Hash Function:', executionTime, 'milliseconds');
            neta = BigInt(neta);

            //Validating if psi and neta are equal or not
            if (psi === neta) {

                console.log("\nAuthentication Successful of gateway at Sensor node(AS)");

                // Compute op1 by doing XOR of gateway secret and response
                const secretBytes1 = [];
                for (let i = 0; i < GS1.length; i += 2) {
                    const byte = parseInt(GS1.substr(i, 2), 16);
                    secretBytes1.push(byte);
                }
             
                const op_1Xor = response.map((num, index) => num ^ secretBytes1[index]);

                const secretBytes2 = [];
                for (let i = 0; i < PIForXOR.length; i += 2) {
                    const byte = parseInt(PIForXOR.substr(i, 2), 16);
                    secretBytes2.push(byte);
                }
                
                const op_1 = op_1Xor.map((num, index) => num ^ secretBytes2[index]);

                const op1 = op_1.join(' ');

                //Compute op2 by doing XOR of gateway secret and sensor id
                const startTime = performance.now();
                const op_2Xor = this.xorStrings(GS1, this.ID);
                const op_2 =  this.xorStrings(op_2Xor,PIForXOR);
                
                const endTime = performance.now();
                const executionTime = endTime - startTime;
                console.log('\nExecution Time of XOR Operation Function:', executionTime, 'milliseconds');

                const m2gs = Date.now() + " " + op1 + " " + op_2 + " " + tHash + " " + CA1;
                const responseMessage = {
                    type: 'M2GS',
                    content: m2gs
                }

                this.sendMessage(socket, responseMessage);
            }
            else {
                console.log("Authentication unsuccessful of gateway at Sensor node(AS) with psi = ", psi, " and neta = ", neta, "\n\n");
            }

        }
        else{
            console.log("ERROR : The Received Message is not FRESH..........");
        }
    }
   
    processM1ASMessage(socket, content) {

       //Registration phase for sensor node begins here 
       console.log(`\nProcessing M1AS message: ${content}\n\n`);

       //Challenge recieved from administrator 
       const challenge = this.convertNumbersStringToByteArray(content);

       //Response generated corresponding to Challenge
       const response = this.generateResponse(challenge);
       const ans = response.join(' ');
       const Ru = response.toString();
       const m1as = this.ID+" "+ans;

        // PUF Challenge
        const responseMessage = {
            type: 'M2AS',
            content: m1as
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
    }

    async processM3ASMessage(socket, content) {

        // Process Type3 message content
        console.log(`Processing M3AS message: ${content}`,"\n\n");

        //Sensor recieves information from Administrator and stores it remotely.
        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        this.keyForAES = parts[4];

        console.log('\nM4UA Message -',"\n\n");
        console.log("Transaction Hash :",this.TH2);
        console.log("Contract Address : ",this.CA);
        console.log("Psuedo Identity : ",this.PI,"\n");
        console.log("Gateway Secret : ",this.GS,"\n\n");
        socket.end();

        

        // Create a connection to the database
        const connection = mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'security123',
            database: 'database1'
        });

        // Connect to the database
        connection.connect((err) => {
            if (err) {
                console.error('Error connecting to database: ' + err.stack);
                return;
            }
        });

        // Define the data you want to insert
        const dataToInsert = [
            [this.TH2, this.CA, this.PI, this.GS,this.ID,this.keyForAES],
        ];

        //Data is inserted in sensor node database
        const sql = 'INSERT INTO collection1 (TH2, CA, PI, GS,sensor_id,keyForAES) VALUES ?';

        // Insert the data into the table
        connection.query(sql, [dataToInsert], (err, results) => {
            if (err) {
                console.error('Error inserting data: ' + err.stack);
                return;
            }
            console.log('Inserted ' + results.affectedRows + ' rows into collection1');
        });
         const endTime = performance.now();
        
        console.log("End  time for registration,",endTime,"milliseconds");
        //Registration Phase ends here

        // Close the connection
        connection.end();

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
    decryptAES(ciphertext, key, iv) {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv, 'hex'));
        let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    bufferTo256BitString(buffer) {
        // Convert buffer to hexadecimal string
        const hexString = buffer.toString('hex');

        // Extract first 256 bits (32 bytes) from hexadecimal string
        const bit256String = hexString.slice(0, 64);

        return bit256String;
    }
}

// Create an instance of the Administrator
const sensor = new Sensor();