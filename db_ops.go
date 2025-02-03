// sample to handle sqlite connection

package main

import (
	"database/sqlite"
	"fmt"
)

func init() {
	db, err = sqlite("SIGNATURE.db")
	fmt.Println("whoami")
	
}
