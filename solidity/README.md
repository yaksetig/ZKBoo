# Solidity SHA256 Verifier

This directory contains `SHA256Verifier.sol`, a Solidity smart contract for verifying SHA-256 commitments.

## Prerequisites

Install the Solidity compiler `solc`:

### Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y solc
```

### Node.js / npm

```bash
npm install -g solc
```

## Local compilation

Compile the contract to obtain bytecode (`.bin`) and the ABI:

```bash
solc --bin --abi SHA256Verifier.sol -o build
```

This command writes `SHA256Verifier.bin` and `SHA256Verifier.abi` to the `build` directory.

## Optional deployment

You can deploy the compiled contract using frameworks like Hardhat or Truffle.

### Hardhat

```bash
npm install --save-dev hardhat
npx hardhat init
# copy SHA256Verifier.sol to hardhat project's contracts/
npx hardhat compile
npx hardhat run scripts/deploy.js --network <network>
```

### Truffle

```bash
npm install -g truffle
truffle init
# copy SHA256Verifier.sol to truffle project's contracts/
truffle compile
truffle migrate --network <network>
```
