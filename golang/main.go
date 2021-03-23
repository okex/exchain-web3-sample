package main

import (
	bytes2 "bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
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

	sampleContractByteCode []byte
	sampleContractABI      abi.ABI
	watch                  = make(chan uint64)
	chainID                = big.NewInt(10)
)

func init() {
	bin, err := ioutil.ReadFile("../test_contract/Storage.bin")
	if err != nil {
		panic(err)
	}
	sampleContractByteCode = common.Hex2Bytes(string(bin))

	abiByte, err := ioutil.ReadFile("../test_contract/Storage.abi")
	if err != nil {
		panic(err)
	}
	sampleContractABI, err = abi.JSON(bytes2.NewReader(abiByte))
	if err != nil {
		panic(err)
	}
}

func main() {
	go watchDB()
	//
	// 0. init
	//
	// 0.1 init client
	client, err := ethclient.Dial(host)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize client: %+v", err))
	}
	// 0.2 get the chain-id from network
	//chainID, err := client.NetworkID(context.Background())
	//if err != nil {
	//	log.Fatalf("failed to fetch the chain-id from network: %+v", err)
	//}
	// 0.3 unencrypted private key -> secp256k1 private key
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		panic(fmt.Sprintf("failed to switch unencrypted private key -> secp256k1 private key: %+v", err))
	}
	// 0.4 secp256k1 private key -> pubkey -> address
	pubkey := privateKey.Public()
	pubkeyECDSA, ok := pubkey.(*ecdsa.PublicKey)
	if !ok {
		panic(fmt.Sprintf("failed to switch secp256k1 private key -> pubkey"))
	}
	fromAddress := crypto.PubkeyToAddress(*pubkeyECDSA)

	// 0.5 get the gasPrice
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		panic(err)
	}

	nonce, err := client.NonceAt(context.Background(), fromAddress, nil)
	if err != nil {
		fmt.Println(err)
	}
	watch <- nonce
	//
	// 1. deploy contract
	//
	contractAddr := deployContract(client, fromAddress, gasPrice, chainID, privateKey)
	fmt.Println(contractAddr)
	//
	// 2. call contract(write)
	//
	nonce, err = client.NonceAt(context.Background(), fromAddress, nil)
	if err != nil {
		fmt.Println(err)
	}
	watch <- nonce

	nonceF := uint64(0)
	count := uint64(0)
	for {
		err := writeContract(client, fromAddress, gasPrice, chainID, privateKey, contractAddr)
		if err != nil {
			continue
		}
		nonce, err := client.NonceAt(context.Background(), fromAddress, nil)
		if err != nil {
			fmt.Println(err)
		}
		if nonce/10 == count+1 && nonce != nonceF {
			watch <- nonce
			nonceF = nonce
			count++
		}
		time.Sleep(time.Second * 3)
	}
	//
	// 3. call contract(read)
	//
	//readContract(client, contractAddr)
}

func watchDB() {
	path := "/root/okexchain/tools/_cache_evm/data"
	for nonce := range watch {
		dirSize := readDir(path)
		fmt.Printf("%d,%0.2f\n", nonce, float64(dirSize)/1024/1024)
	}
}

func readDir(dirPath string) (dirSize int64) {
	flist, e := ioutil.ReadDir(dirPath)
	if e != nil {
		fmt.Println("read file error")
		return
	}
	for _, f := range flist {
		if f.IsDir() {
			dirSize = readDir(dirPath+"/"+f.Name()) + dirSize
		} else {
			dirSize = f.Size() + dirSize
		}
	}
	return dirSize
}

func deployContract(client *ethclient.Client,
	fromAddress common.Address,
	gasPrice *big.Int,
	chainID *big.Int,
	privateKey *ecdsa.PrivateKey) (contractAddr common.Address) {
	// 0. get the value of nonce, based on address
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		panic(fmt.Sprintf("failed to fetch the value of nonce from network: %+v", err))
	}

	//1. simulate unsignedTx as you want, fill out the parameters into a unsignedTx
	unsignedTx := deployContractTx(nonce, gasPrice)

	// 2. sign unsignedTx -> rawTx
	signedTx, err := types.SignTx(unsignedTx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		panic(fmt.Sprintf("failed to sign the unsignedTx offline: %+v", err))
	}

	// 3. send rawTx
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		panic(err)
	}

	// 4. get the contract address based on tx hash
	hash := getTxHash(signedTx)
	//hash := signedTx.Hash()
	time.Sleep(time.Second * 10)

	receipt, err := client.TransactionReceipt(context.Background(), hash)
	if err != nil {
		panic(err)
	}

	return receipt.ContractAddress
}

func deployContractTx(nonce uint64, gasPrice *big.Int) *types.Transaction {
	value := big.NewInt(0)
	gasLimit := uint64(3000000)

	// Constructor
	input, err := sampleContractABI.Pack("")
	if err != nil {
		panic(err)
	}
	data := append(sampleContractByteCode, input...)
	return types.NewContractCreation(nonce, value, gasLimit, gasPrice, data)
}

func writeContract(client *ethclient.Client,
	fromAddress common.Address,
	gasPrice *big.Int,
	chainID *big.Int,
	privateKey *ecdsa.PrivateKey,
	contractAddr common.Address) error {
	// 0. get the value of nonce, based on address
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Printf("failed to fetch the value of nonce from network: %+v", err)
		return err
	}

	unsignedTx := writeContractTx(nonce, contractAddr, gasPrice)
	// 2. sign unsignedTx -> rawTx
	signedTx, err := types.SignTx(unsignedTx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Printf("failed to sign the unsignedTx offline: %+v", err)
		return err
	}

	// 3. send rawTx
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func writeContractTx(nonce uint64, contractAddr common.Address, gasPrice *big.Int) *types.Transaction {
	value := big.NewInt(0)
	gasLimit := uint64(30000000)

	//num := big.NewInt(999)
	data, err := sampleContractABI.Pack("add")
	if err != nil {
		fmt.Println(err)
	}
	return types.NewTransaction(nonce, contractAddr, value, gasLimit, gasPrice, data)
}

func readContract(client *ethclient.Client, contractAddr common.Address) {
	data, err := sampleContractABI.Pack("retrieve")
	if err != nil {
		panic(err)
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
		panic(err)
	}

	tx := new(evmtypes.MsgEthereumTx)
	// RLP decode raw transaction bytes
	if err := rlp.DecodeBytes(rawTxBytes, tx); err != nil {
		panic(err)
	}

	cdc := codec.MakeCodec(app.ModuleBasics)
	txEncoder := authclient.GetTxEncoder(cdc)
	txBytes, err := txEncoder(tx)
	if err != nil {
		panic(err)
	}

	var hexBytes bytes.HexBytes
	hexBytes = tmhash.Sum(txBytes)
	hash := common.HexToHash(hexBytes.String())
	return hash
}
