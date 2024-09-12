package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"time"

	"github.com/Thankgod20/miniBTCD/blockchain"
	"github.com/Thankgod20/miniBTCD/mining"

	"github.com/go-redis/redis/v8"
)

type MineAddr struct {
	Address []string `json:"Address"`
}

func main() {

	miningx := flag.Bool("mining", false, "Enable Mining")
	selemine := flag.Bool("smining", false, "Enable Mining")
	mineaddr := flag.String("mineaddr", "", "Address Allowed to Mine")
	timinng := flag.Int("time", -1, "Mining Ever Minutes")
	address := flag.String("address", "", "Miner Address")
	flag.Parse()

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Update with your Redis server address
		// add more options if needed
	})

	// Initialize blockchain
	bc := blockchain.NewBlockchain(rdb, *address)
	log.Println("Start")
	switch {
	case *miningx:
		log.Println("Mining Enabled")

		switch {
		case *address != "":
			go func(miner string) {
				bc.MinersAddress(miner)
				log.Println("Miner Address Added", bc.Mempool.Miner)
			}(*address)
			switch {
			case *timinng != -1:
				log.Println("Mining Time")
				var mine bool
				var min_mine int
				mine = true
				min_mine = *timinng
				if *selemine {
					log.Println("** Selected Mining Started **")
					go func() {
						for {
							log.Printf("Mining Every %d minue", min_mine)
							time.Sleep(time.Duration(min_mine) * time.Minute)

							mine_address, err := os.Open(*mineaddr)
							if err != nil {
								log.Fatal(err)
							}

							//Read the file
							byteValue, err := ioutil.ReadAll(mine_address)
							if err != nil {
								log.Fatal(err)
							}
							var data MineAddr
							err = json.Unmarshal(byteValue, &data)
							if err != nil {
								log.Fatal(err)
							}
							for _, addr := range data.Address {
								//fmt.Println("Address:-", addr)
								trns := bc.Mempool.GetTransactions()
								allowMine := mining.CheckInputAddress(trns, bc, addr)
								if allowMine {
									log.Println("Transaction Found and Address Allowed!!! Mining Transactions To BlockChain")
									mining.AddBlock(trns, bc)
								}
							}
						}
					}()

				} else {
					go func() {
						for {
							if mine {
								log.Printf("Mining Every %d minue", min_mine)
								time.Sleep(time.Duration(min_mine) * time.Minute)
								log.Println("Checking Mempool for Transactions")
								trns := bc.Mempool.GetTransactions()

								if len(trns) > 0 {

									log.Println("Transaction Found !!! Mining Transactions To BlockChain")
									mining.AddBlock(trns, bc)
								}
							}
						}
					}()
				}
			}
		default:
			log.Println("Must Enter Mining Time")
		}

	}
	// Register the RPC service
	rpc.Register(bc)
	// Start listening for RPC requests
	listener, err := net.Listen("tcp", ":18885")
	if err != nil {
		log.Fatalf("Failed to start RPC server: %v", err)
	}
	defer listener.Close()

	log.Println("Starting RPC server on :18885")
	for {

		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go rpc.ServeConn(conn)

	}
}

/*
// HTTP routes

		http.HandleFunc("/block/latest", handleGetLatestBlock(bc))

		// Start server
		log.Println("Starting HTTP server on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}
*/

func handleGetLatestBlock(bc *blockchain.Blockchain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(bc.Blocks) == 0 {
			http.Error(w, "Blockchain is empty", http.StatusNotFound)
			return
		}

		latestBlock := bc.Blocks[len(bc.Blocks)-1]
		jsonBlock, err := json.Marshal(latestBlock)
		if err != nil {
			http.Error(w, "Failed to marshal block", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonBlock)
	}
}
