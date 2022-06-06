const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;
const secp = require("@noble/secp256k1");
const {keccak_256} = require('@noble/hashes/sha3');
const { bytesToHex } = require('@noble/hashes/utils');
// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

// generate private key and convert it to hex
let privateKey1 = secp.utils.randomPrivateKey();
privateKey1 = Buffer.from(privateKey1).toString("hex");

let privateKey2 = secp.utils.randomPrivateKey();
privateKey2 = Buffer.from(privateKey2).toString("hex");

let privateKey3 = secp.utils.randomPrivateKey();
privateKey3 = Buffer.from(privateKey3).toString("hex");

// use above private key to derive public key
// then turn it to hex and slice off last 40 characters
let publicKey1 = secp.getPublicKey(privateKey1);
publicKey1 = Buffer.from(publicKey1).toString("hex");
publicKey1 = "0x" + publicKey1.slice(publicKey1.length - 40);
console.log(publicKey1);

let publicKey2 = secp.getPublicKey(privateKey2);
publicKey2 = Buffer.from(publicKey2).toString("hex");
publicKey2 = "0x" + publicKey2.slice(publicKey2.length - 40);
console.log(publicKey2);

let publicKey3 = secp.getPublicKey(privateKey3);
publicKey3 = Buffer.from(publicKey3).toString("hex");
publicKey3 = "0x" + publicKey3.slice(publicKey3.length - 40);
console.log(publicKey3);

const walletKeys = new Map();
walletKeys.set(publicKey1, privateKey1);
walletKeys.set(publicKey2, privateKey2);
walletKeys.set(publicKey3, privateKey3)
console.log(walletKeys)

const balances = new Map();
balances.set(publicKey1, 100);
balances.set(publicKey2, 100);
balances.set(publicKey3, 100)
console.log(balances)

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances.get(address) || 0;
  res.send({ balance });
});

app.post("/send", async (req, res) => {
  const { sender, recipient, amount } = req.body;
  balances.set(sender, balances.get(sender) - amount);
  balances.set(recipient, (balances.get(recipient) || 0) + +amount);
  
  const messageHash = bytesToHex(keccak_256(balances.get(sender).toString()));

  const signature = await secp.sign(messageHash, walletKeys.get(sender));
  const isSigned = secp.verify(signature, messageHash, sender);
  console.log("walletKeys.get(sender)", walletKeys.get(sender))
  console.log("sender", sender)

  isSigned ? res.send({ balance: balances.get(sender), signed: isSigned }) : res.send({ balance: "Transaction reversed because it cannot be verified", signed: isSigned });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
