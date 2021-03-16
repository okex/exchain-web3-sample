package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	authclient "github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/okex/okexchain/app"
	"github.com/okex/okexchain/app/codec"
	evmtypes "github.com/okex/okexchain/x/evm/types"
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/bytes"
)

var (
	host    = "http://localhost:8545"
	privKey = "e47a1fe74a7f9bfa44a362a3c6fbe96667242f62e6b8e138b3f61bd431c3215d"

	sampleContractByteCode = common.Hex2Bytes("608060405234801561001057600080fd5b5060c78061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d146053575b600080fd5b603d607e565b6040518082815260200191505060405180910390f35b607c60048036036020811015606757600080fd5b81019080803590602001909291905050506087565b005b60008054905090565b806000819055505056fea2646970667358221220e102a9b12d5fffc915bf859246f362c24f40a7752ea826e7fe9c5e640bcd6d4a64736f6c63430007060033")
	sampleContractABIStr   = `
[
	{
		"inputs": [],
		"name": "retrieve",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "num",
				"type": "uint256"
			}
		],
		"name": "store",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`
	sampleContractABI, _ = abi.JSON(strings.NewReader(sampleContractABIStr))
)

// Sample contract:
//http://remix.ethereum.org/#optimize=true&runs=200&evmVersion=null&version=soljson-v0.7.6+commit.7338295f.js
//1_Storage.sol
//
//// SPDX-License-Identifier: GPL-3.0
//
//pragma solidity >=0.7.0 <0.8.0;
//
///**
// * @title Storage
// * @dev Store & retrieve value in a variable
// */
//contract Storage {
//
//uint256 number;
//
///**
// * @dev Store value in variable
// * @param num value to store
// */
//function store(uint256 num) public {
//number = num;
//}
//
///**
// * @dev Return value
// * @return value of 'number'
// */
//function retrieve() public view returns (uint256){
//return number;
//}
//}

func main() {
	//
	// 0. init
	//
	// 0.1 init client
	client, err := ethclient.Dial(host)
	if err != nil {
		log.Fatalf("failed to initialize client: %+v", err)
	}
	// 0.2 get the chain-id from network
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("failed to fetch the chain-id from network: %+v", err)
	}
	// 0.3 unencrypted private key -> secp256k1 private key
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		log.Fatalf("failed to switch unencrypted private key -> secp256k1 private key: %+v", err)
	}
	// 0.4 secp256k1 private key -> pubkey -> address
	pubkey := privateKey.Public()
	pubkeyECDSA, ok := pubkey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalln("failed to switch secp256k1 private key -> pubkey")
	}
	fromAddress := crypto.PubkeyToAddress(*pubkeyECDSA)

	// 0.5 get the gasPrice
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	//
	// 1. deploy contract
	//
	contractAddr := deployContract(client, fromAddress, gasPrice, chainID, privateKey)
	//
	// 2. call contract(write)
	//
	writeContract(client, fromAddress, gasPrice, chainID, privateKey, contractAddr)
	time.Sleep(time.Second * 3)
	//
	// 3. call contract(read)
	//
	readContract(client, contractAddr)
}

func deployContract(client *ethclient.Client,
	fromAddress common.Address,
	gasPrice *big.Int,
	chainID *big.Int,
	privateKey *ecdsa.PrivateKey) (contractAddr common.Address) {
	// 0. get the value of nonce, based on address
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to fetch the value of nonce from network: %+v", err)
	}

	//1. simulate unsignedTx as you want, fill out the parameters into a unsignedTx
	unsignedTx := deployContractTx(nonce, gasPrice)

	// 2. sign unsignedTx -> rawTx
	signedTx, err := types.SignTx(unsignedTx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("failed to sign the unsignedTx offline: %+v", err)
	}

	// 3. send rawTx
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	// 4. get the contract address based on tx hash
	hash := getTxHash(signedTx)
	time.Sleep(time.Second * 5)

	receipt, err := client.TransactionReceipt(context.Background(), hash)
	if err != nil {
		log.Fatal(err)
	}

	return receipt.ContractAddress
}

func deployContractTx(nonce uint64, gasPrice *big.Int) *types.Transaction {
	value := big.NewInt(0)
	gasLimit := uint64(3000000)

	// Constructor
	input, err := sampleContractABI.Pack("")
	if err != nil {
		log.Fatal(err)
	}
	data := append(sampleContractByteCode, input...)
	return types.NewContractCreation(nonce, value, gasLimit, gasPrice, data)
}

func writeContract(client *ethclient.Client,
	fromAddress common.Address,
	gasPrice *big.Int,
	chainID *big.Int,
	privateKey *ecdsa.PrivateKey,
	contractAddr common.Address) {
	// 0. get the value of nonce, based on address
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to fetch the value of nonce from network: %+v", err)
	}

	unsignedTx := writeContractTx(nonce, contractAddr, gasPrice)
	// 2. sign unsignedTx -> rawTx
	signedTx, err := types.SignTx(unsignedTx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("failed to sign the unsignedTx offline: %+v", err)
	}

	// 3. send rawTx
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}
}

func writeContractTx(nonce uint64, contractAddr common.Address, gasPrice *big.Int) *types.Transaction {
	value := big.NewInt(0)
	gasLimit := uint64(3000000)

	num := big.NewInt(999)
	data, err := sampleContractABI.Pack("store", num)
	if err != nil {
		log.Fatal(err)
	}
	return types.NewTransaction(nonce, contractAddr, value, gasLimit, gasPrice, data)
}

func readContract(client *ethclient.Client, contractAddr common.Address) {
	data, err := sampleContractABI.Pack("retrieve")
	if err != nil {
		log.Fatal(err)
	}

	msg := ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}

	output, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		panic(err)
	}

	ret, err := sampleContractABI.Unpack("retrieve", output)
	if err != nil {
		panic(err)
	}
	fmt.Println(ret)
}

func getTxHash(signedTx *types.Transaction) common.Hash {
	ts := types.Transactions{signedTx}
	rawTx := hex.EncodeToString(ts.GetRlp(0))

	rawTxBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		log.Fatal(err)
	}

	tx := new(evmtypes.MsgEthereumTx)
	// RLP decode raw transaction bytes
	if err := rlp.DecodeBytes(rawTxBytes, tx); err != nil {
		log.Fatal(err)
	}

	cdc := codec.MakeCodec(app.ModuleBasics)
	txEncoder := authclient.GetTxEncoder(cdc)
	txBytes, err := txEncoder(tx)
	if err != nil {
		log.Fatal(err)
	}

	var hexBytes bytes.HexBytes
	hexBytes = tmhash.Sum(txBytes)
	hash := common.HexToHash(hexBytes.String())
	return hash
}
