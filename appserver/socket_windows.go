//go:build windows

package appserver

import "os"

// Windows local socket access is governed by the user's cache directory ACL.
func ownedByCurrentUser(info os.FileInfo) bool { return true }
