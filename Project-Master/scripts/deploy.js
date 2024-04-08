// imports
const { ethers, run, network } = require("hardhat")

// async main
async function main() {
  try
  {
  const IoTContract = await ethers.getContractFactory("IoT")
  console.log("Deploying contract...")
  const lock= await IoTContract.deploy()

  // Not functionable in version 6^ ethers ----->
  
  // await simpleStorage.deployed()
  // console.log(`Deployed contract to: ${simpleStorage.address}`)

  //______________________________________________
  
  // what happens when we deploy to our hardhat network?
  // if (network.config.chainId === 11155111 && process.env.ETHERSCAN_API_KEY) {
  //   console.log("Waiting for block confirmations...")

  //   // Not functionable in version 6^ ethers ----->
    
  //   await simpleStorage.deploymentTransaction().wait(6)
  //   await verify(simpleStorage.target, [])

  //   //______________________________________________

    
  // }

  // const currentValue = await simpleStorage.retrieve()
  // console.log(`Current Value is: ${currentValue}`)

  // // Update the current value
  // const transactionResponse = await simpleStorage.store(7)
  // await transactionResponse.wait(1)
  // const updatedValue = await simpleStorage.retrieve()
  // console.log(`Updated Value is: ${updatedValue}`)
  const txReceipt = await lock.deployTransaction.wait();

    console.log('Deployment Details:');
    console.log('-------------------');
    console.log('Transaction Hash:', txReceipt.transactionHash);
    console.log('Block Number:', txReceipt.blockNumber);
    console.log('Contract Creator:', txReceipt.from);
    console.log('Contract Address:', lock.address);
    console.log('Transaction Fee:', ethers.utils.formatEther(txReceipt.gasUsed.mul(lock.deployTransaction.gasPrice)));
    console.log('Gas Used in Transaction:', txReceipt.gasUsed.toString());

    // Access events/logs directly
    console.log('Transaction Events:', txReceipt.logs);
  } catch (error) {
    console.error('Deployment failed:', error);
    process.exitCode = 1;
  }
  
}

// async function verify(contractAddress, args) {
// const verify = async (contractAddress, args) => {
//   console.log("Verifying contract...")
//   try {
//     await run("verify:verify", {
//       address: contractAddress,
//       constructorArguments: args,
//     })
//   } catch (e) {
//     if (e.message.toLowerCase().includes("already verified")) {
//       console.log("Already Verified!")
//     } else {
//       console.log(e)
//     }
//   }
// }

// main
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
