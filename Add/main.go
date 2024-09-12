package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type Data struct {
	Address []string `json:"Address"`
}

func main() {
	// Open the JSON file
	fileName := "../RPCServer/addresses.json"
	jsonFile, err := os.Open(fileName)
	if err != nil {
		// If file does not exist, create an empty structure
		fmt.Println("File not found, creating a new one.")
		jsonFile = nil
	} else {
		defer jsonFile.Close()
	}

	var data Data

	// If the file exists, read and unmarshal the existing data
	if jsonFile != nil {
		byteValue, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Unmarshal existing JSON data into the struct
		err = json.Unmarshal(byteValue, &data)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Take address input from the user
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the new address: ")
	newAddress, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	// Trim the newline character from the input
	newAddress = strings.TrimSpace(newAddress)

	// Append the new address to the Address array
	data.Address = append(data.Address, newAddress)

	// Marshal the updated data back to JSON format
	updatedData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Write the updated data back to the file
	err = ioutil.WriteFile(fileName, updatedData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Updated Address array successfully written to the file.")
}
