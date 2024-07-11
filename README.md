# miniBTCD

**miniBTCD** is a Golang-based Bitcoin solo node or mock node designed for simulation purposes. It can process mainnet transactions but lacks the P2P network peering feature. This project is ideal for those looking to understand Bitcoin transactions and node operations in a simplified, controlled environment.

## Features

### Server

- **Mining Capability**: The server includes functionality to mine new blocks.

### Client

- **Wallet Operations**:
  - Create P2PKH (Pay-to-PubKey-Hash) wallets
  - Create P2SH (Pay-to-Script-Hash) wallets
  - Create P2WPKH (Pay-to-Witness-PubKey-Hash) wallets
- **Transaction Operations**:
  - Create transactions for P2PKH, P2SH, and P2WPKH addresses
  - Check wallet balance
  - Get address transaction history
  - Retrieve block hex data
  - Retrieve transaction details by ID

## Getting Started

### Prerequisites

Ensure you have Golang installed on your machine. You can download it from [here](https://golang.org/dl/).

### Installation

Clone the repository:

```sh
git clone https://github.com/Thankgod20/miniBTCD.git
cd miniBTCD
```

### Running the Server

The server handles the blockchain operations and provides an RPC interface for interaction. It also has optional mining capabilities.

### Prerequisites

Ensure you have Redis installed and running on your machine as it is used for the blockchain state management. You can download Redis from [here](https://redis.io/download).

### Running the Server

Navigate to the `RPCServer` folder and run the server:

```sh
cd RPCServer
go run main.go [OPTIONS]
```

### Available Options

- `--mining` : Enable mining.
- `--time <minutes>` : Specify the interval for mining in minutes.
- `--address <miner_address>` : Specify the miner address for mining rewards.

### Examples

#### Start the Server without Mining

```sh
go run main.go
```

#### Start the Server with Mining Enabled

To enable mining, provide the `--mining` flag along with the `--address` of the miner and the `--time` interval in minutes:

```sh
go run main.go --mining --address="your-miner-address" --time=10
```

Starting The blockchain for the first time, the miner-address is same as the first genesis address to recieve the first 1000 BTC

### How the Server Works

1. **Initialize Redis Client**: The server initializes a Redis client to manage the blockchain state.
2. **Initialize Blockchain**: The blockchain is initialized with the Redis client.
3. **Mining**: If mining is enabled, the server will periodically check the mempool for transactions and mine new blocks at the specified interval.
4. **Register RPC Service**: The server registers the blockchain as an RPC service and starts listening for RPC requests on port 18885.

### Mining Functionality

When mining is enabled, the server performs the following steps:

1. **Set Miner Address**: The specified miner address is set for mining rewards.
2. **Check Mempool**: The server periodically checks the mempool for transactions.
3. **Mine Transactions**: If transactions are found in the mempool, they are mined into a new block and added to the blockchain.

### RPC Endpoints

The server exposes the following RPC endpoints for client interactions:

- **GetLatestBlock**: Retrieves the latest block in the blockchain.
- **GetTransactionHistory**: Retrieves the transaction history for a specified address.
- **GetBlockRPC**: Retrieves block details by block ID.
- **VerifyTX**: Verifies a transaction by its ID.
- **GetTX**: Retrieves transaction details by its ID.
- **GetCurrentHeight**: Retrieves the current height of the blockchain.
- **GetBalance**: Retrieves the balance of a specified wallet address.
- **GetAddressUTXOs**: Retrieves the UTXOs for a specified wallet address.
- **AddToMempool**: Adds a transaction to the mempool for mining.

### HTTP Interface (Optional)

The server also has an optional HTTP interface to retrieve the latest block. Uncomment the HTTP route section in the code to enable it.

#### Start the HTTP Server

To start the HTTP server, uncomment the following lines in the code:

```go
http.HandleFunc("/block/latest", handleGetLatestBlock(bc))
log.Println("Starting HTTP server on :8080")
log.Fatal(http.ListenAndServe(":8080", nil))
```

### Example HTTP Request

#### Get Latest Block

To get the latest block via HTTP:

```sh
curl http://localhost:8080/block/latest
```

This will return the latest block in the blockchain in JSON format.

### Running the Client

The client allows you to perform various operations such as creating wallets, making transactions, checking balances, and more. Here are the detailed instructions for using the client:

### Prerequisites

Ensure that the server is running before you start the client. Refer to the [Running the Server](#running-the-server) section for instructions.

### Running the Client

Navigate to the `client` folder and run the client:

```sh
cd client
go run main.go [OPTIONS]
```

### Available Options

- `--latestblock` : Get the latest block.
- `--blockheight` : Get the current block height.
- `--newWallet <seed>` : Create a new wallet using the provided seed phrase.
- `--wallet` : Wallet-related operations. Use additional flags like `--balance`, `--address`, or `--createtx` for specific actions.
- `--balance <address>` : Check the balance of the specified wallet address.
- `--address <address>` : Specify the wallet address for operations.
- `--createtx <passphrase>` : Create a new transaction. Use additional flags like `--to`, `--amount`, `--wallettype`, and `--fees`.
- `--to <address>` : Specify the recipient's address for the transaction.
- `--amount <value>` : Specify the amount for the transaction.
- `--fees <value>` : Specify the transaction fee.
- `--decodetx <hex>` : Decode a transaction from its hex representation.
- `--bech32` : Use Bech32 address format for wallet creation.
- `--p2pkh` : Use P2PKH address format for wallet creation.
- `--p2sh` : Use P2SH address format for wallet creation.
- `--broadcast <hex>` : Broadcast a transaction using its hex representation.
- `--verifytxID <txID>` : Verify a transaction by its ID.
- `--getTrx <txID>` : Get transaction details by its ID.
- `--getblock <blockID>` : Get block details by its ID.
- `--trnxs <address>` : Get transaction history for a specified address.

### Examples

#### Get Latest Block

```sh
go run main.go --latestblock
```

#### Get Current Block Height

```sh
go run main.go --blockheight
```

#### Create a New Wallet

```sh
go run main.go --newWallet="your-seed-phrase" --bech32
```

or

```sh
go run main.go --newWallet="your-seed-phrase" --p2pkh
```

or

```sh
go run main.go --newWallet="your-seed-phrase" --p2sh
```

#### Check Wallet Balance

```sh
go run main.go --wallet --balance="wallet-address"
```

#### Create a Transaction

```sh
go run main.go --wallet --createtx="your-seed-phrase" --to="recipient-address" --amount=10 --wallettype="p2pkh" --fees=0.0001
```

#### Decode a Transaction

```sh
go run main.go --decodetx="transaction-hex"
```

#### Broadcast a Transaction

```sh
go run main.go --broadcast="transaction-hex"
```

#### Verify a Transaction

```sh
go run main.go --verifytxID="transaction-id"
```

#### Get Transaction Details

```sh
go run main.go --getTrx="transaction-id"
```

#### Get Block Details

```sh
go run main.go --getblock="block-id"
```

#### Get Address Transaction History

```sh
go run main.go --trnxs="wallet-address"
```

## Usage

Once the server and client are running, you can interact with the node using the client to perform various operations such as creating wallets, making transactions, checking balances, and more.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or issues, please open an issue on the repository or contact me directly.

---

Feel free to adjust any details to better suit your preferences or additional information you might want to include.
