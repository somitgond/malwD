package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var db *sql.DB // Global variable
var total int
var scannedPIDs = make(map[int]bool) // Keep track of scanned PIDs

func initDB() {
	// database file name
	dbFile := "SIGNATURES.db"

	var err error

	// Open database connection
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}

	// Create table if it does not exist
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS SIGNATURES (SIGN CHAR(64) PRIMARY KEY NOT NULL)")
	if err != nil {
		log.Fatal(err)
	}
}

func file_exists(file_path string) bool {
	_, err := os.Stat(file_path)
	return !errors.Is(err, os.ErrNotExist)

}

func directory_exists(directory_path string) bool {
	if _, err := os.Stat(directory_path); err == nil {
		return true
	}
	return false
}

func file_hash(file_path string) string {
	file, err := os.Open(file_path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func checkSignatureInDB(db *sql.DB, signature string) bool {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM SIGNATURES WHERE SIGN=?)"
	err := db.QueryRow(query, signature).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err) // Handle unexpected errors
	}
	return exists
}

func addSignature(db *sql.DB, signature string) error {
	query := "INSERT INTO SIGNATURES (SIGN) VALUES (?)"
	_, err := db.Exec(query, signature)
	if err != nil {
		return err // Return error if insertion fails
	}
	return nil
}

func scanFile(filePath string) {
	fmt.Println("Scanning executable:", filePath)
	signature := file_hash(filePath)
	if checkSignatureInDB(db, signature) {
		total += 1
		fmt.Println("###############################################################")
		fmt.Printf("%s: Signature exists in DB. Maybe a malware.\n", filePath)
		fmt.Println("###############################################################")
	} else {
		fmt.Println("Signature not found in DB.")
	}
}

func scanDirectory(root string) {
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Println("Error:", err)
			return nil
		}

		if d.IsDir() {
			fmt.Println("Directory:", path)
		} else {
			scanFile(path) // Call scanFile if it's a file
		}
		return nil
	})

	if err != nil {
		fmt.Println("Failed to scan directory:", err)
	}
}

func monitorDirectory(dir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Add directory to the watcher
	err = watcher.Add(dir)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Monitoring directory:", dir)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// Check if a new file is created
			if event.Op&fsnotify.Create == fsnotify.Create {
				time.Sleep(500 * time.Millisecond) // Small delay to ensure file is written
				fileInfo, err := os.Stat(event.Name)
				if err == nil && !fileInfo.IsDir() {
					scanFile(event.Name)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error:", err)
		}
	}
}

func killProcess(pid int) {
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("Failed to find process %d: %v\n", pid, err)
		return
	}

	// Send SIGKILL to terminate the process
	err = process.Signal(syscall.SIGKILL)
	if err != nil {
		fmt.Printf("Failed to kill process %d: %v\n", pid, err)
	} else {
		fmt.Printf("Killed process %d running malicious executable.\n", pid)
	}
}

func monitorProcesses() {
	fmt.Println("Monitoring processes in real-time...")

	for {
		procDir := "/proc"
		entries, err := os.ReadDir(procDir)
		if err != nil {
			log.Println("Error reading /proc:", err)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				// Convert directory name (PID) to an integer
				pid, err := strconv.Atoi(entry.Name())
				if err != nil {
					continue // Skip non-numeric directories
				}

				// Skip if already scanned
				if scannedPIDs[pid] {
					continue
				}

				// Get the executable path
				exePath := filepath.Join(procDir, entry.Name(), "exe")
				executable, err := os.Readlink(exePath)
				if err == nil {
					filePath := executable
					fmt.Println("Scanning executable:", filePath)
					signature := file_hash(filePath)
					if checkSignatureInDB(db, signature) {
						total += 1
						fmt.Println("###############################################################")
						fmt.Printf("%s: Signature exists in DB. Maybe a malware.\n", filePath)
						fmt.Println("###############################################################")
						killProcess(pid)
					} else {
						fmt.Println("Signature not found in DB.")
					}
					//scanFile(executable)
					scannedPIDs[pid] = true // Mark as scanned
				}
			}
		}

		time.Sleep(2 * time.Second) // Adjust delay as needed
	}
}

func main() {
	// initialize database connection
	initDB()
	defer db.Close()

	// hard coded malware signatures
	malware_signatures := []string{
		"244591cb0ce6c918ce44073ca88f6d86eda7bea01452db13d042ff95263bde10",
		"e1321a4b2b104f31aceaf4b19c5559e40ba35b73a754d3ae13d8e90c53146c0f",
		"74f497088b49b745e6377b32ed5d9dfaef3c84c7c0bb50fabf30363ad2e0bfb1",
		"3d2b58ef6df743ce58669d7387ff94740ceb0122c4fc1c4ffd81af00e72e60a4",
		"30430bcfeee8141ba1dba3983c9a8d89f3c1acf5b8efd0d97f23d4a122c0787a",
		"f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf",
		"718d6f185fdc2d9fd206914c2b05f85e3c50b53c705071c09cebdf44cff34768",
		"43c5a487329f5d6b4a6d02e2f8ef62744b850312c5cb87c0a414f3830767be72",
		"8e9a33809b9062c5033928f82e8adacbef6cd7b40e73da9fcf13ec2493b4544c",
		"c0869e7f1bb4914fa453db5eb9cafd6fea090f7c6c156b9f1a3479e0ce7f4df2",
		"2c14356e0a6a9019c50b069e88fe58abbbc3c93451a74e3e66f8c1a2a831e9ba",
	}

	for _, ss := range malware_signatures {
		if !checkSignatureInDB(db, ss) {
			if err := addSignature(db, ss); err != nil {
				fmt.Println("Error inserting signature:", err)
			} else {
				//fmt.Println("Signature added successfully.")
			}
		}
	}

	fmt.Println(`Welcome to malware detector
1. To scan a file
2. To scan a folder/directory
3. To insert a signature in database
4. Scan a folder in real time
5. Scan processes in real time 
6. To exit`)
	var user_input int
	fmt.Scanln(&user_input)

	fmt.Printf("Your input number is: %d \n", user_input)

	// based on user input decide what to
	switch user_input {
	case 1:
		fmt.Print("Input file path: ")
		var file_path string
		fmt.Scanln(&file_path)
		//		file_path = "/home/jack/github/malwD/" + file_path
		fmt.Printf("Your input file is: %s\n", file_path)

		// check if file exists or not
		if file_exists(file_path) {
			fmt.Println("File exists")
			scanFile(file_path)
		}

	case 2:
		fmt.Print("Input directory path: ")
		var directory_path string
		fmt.Scanln(&directory_path)
		fmt.Printf("Your input directory is: %s\n", directory_path)

		// scan the directory
		if directory_exists(directory_path) {
			scanDirectory(directory_path)
		}

	case 3:
		fmt.Print("Input file signature: ")
		var file_signature string
		fmt.Scanln(&file_signature)

		if err := addSignature(db, file_signature); err != nil {
			fmt.Println("Error inserting signature:", err)
		} else {
			fmt.Println("Signature added successfully.")
		}

	case 4:
		fmt.Print("Input directory path: ")
		var directory_path string
		fmt.Scanln(&directory_path)

		if directory_exists(directory_path) {
			monitorDirectory(directory_path)
		}

	case 5:
		fmt.Println("Start scanning processes....")
		fmt.Println("Superuser permission required for scanning processes from root or other users.")
		//getProcessExecutables()
		monitorProcesses()

	case 6:
		fmt.Print("Exiting...\n")
		fmt.Println("not printing")
		os.Exit(0)
	}
	fmt.Printf("%d malware found. \n", total)
}
