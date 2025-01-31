// sample to handle sqlite connection

package main

import (
	"database/sqlite"
)

func init() {
	db, err = sqlite("SIGNATURE.db")
}
