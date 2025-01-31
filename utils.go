// utility functions

package main

import (
	"os"
	//"fmt"
	"errors"
)

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
