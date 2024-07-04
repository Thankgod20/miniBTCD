package main

import (
	"encoding/json"
	"flag"
	"log"
	"minibtcd/blockchain"
	"minibtcd/mining"
	"net"
	"net/http"
	"net/rpc"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {

	miningx := flag.Bool("mining", false, "Enable Mining")
	timinng := flag.Int("time", -1, "Mining Ever Minutes")
	address := flag.String("address", "", "Miner Address")
	flag.Parse()

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Update with your Redis server address
		// add more options if needed
	})

	// Initialize blockchain
	bc := blockchain.NewBlockchain(rdb)
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

	log.Println("Starting RPC server on :X18885")
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
