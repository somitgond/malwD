package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println(`Welcome to malware detector
1. To scan a file
2. To scan a folder/directory
3. To insert a signature in database
4. Scan a folder in real time
5. To exit`)
	var user_input int
	fmt.Scanln(&user_input)

	fmt.Printf("Your input number is: %d \n", user_input)
	
	// based on user input decide what to do
	switch user_input {
	case 1:
		fmt.Print("Input file path: ")
		var file_path string
		fmt.Scanln(&file_path);		
		fmt.Printf("Your input file is: %s\n", file_path)

		// check if file exists or not
		// if file_exist(file_path) {
		// scan_file(file_path)
		// }
	case 2:
		fmt.Print("Input directory path: ")
		var directory_path string
		fmt.Scanln(&directory_path);
		fmt.Printf("Your input directory is: %s\n", directory_path)
		
		// check if file exists or not
		// if directory_exist(directory_path) {
		// directory_file(directory_path)
		// }
	case 3:
		fmt.Print("Input file signature: ")
		var file_signature string
		fmt.Scanln(&file_signature);

		fmt.Printf("Your input file signature is: %s\n", file_signature)
		// insert into the database
		// insert_file_sig(file_signature)
	case 4:
		fmt.Print("Input directory path: ")
		var directory_path string
		fmt.Scanln(&directory_path);
		fmt.Printf("Your input directory is: %s\n", directory_path)

		// check if file exists or not
		// if directory_exist(directory_path) {
		// directory_file(directory_path)
	case 5:
		fmt.Print("Exiting...\n")
		os.Exit(0)
		
	}

}
