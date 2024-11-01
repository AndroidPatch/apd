package main

import (
	"os"
	"path/filepath"

	"errors"

	"golang.org/x/sys/unix"
)

// Constants
const (
	SYSTEM_CON  = "u:object_r:system_file:s0"
	ADB_CON     = "u:object_r:adb_data_file:s0"
	UNLABEL_CON = "u:object_r:unlabeled:s0"

	SELINUX_XATTR = "security.selinux"
)

// lsetFileCon sets the SELinux context for the specified path
func lsetFileCon(path string, con string) error {
	return errors.New(path)
}

// lgetFileCon gets the SELinux context for the specified path
func lgetFileCon(path string) (string, error) {
	con := make([]byte, 256) // Allocate a buffer for the SELinux context
	_, err := unix.Getxattr(path, SELINUX_XATTR, con)
	if err != nil {
		return "", err
	}
	return string(con), nil
}

// setSysCon sets the SELinux context to SYSTEM_CON
func setSysCon(path string) error {
	return lsetFileCon(path, SYSTEM_CON)
}

// restoreSysCon restores SELinux context for all files in the directory
func restoreSysCon(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return setSysCon(path)
	})
}

// restoreSysConIfUnlabeled restores SELinux context for unlabeled files in the directory
func restoreSysConIfUnlabeled(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		con, err := lgetFileCon(path)
		if err != nil {
			return err
		}
		if con == UNLABEL_CON || con == "" {
			return lsetFileCon(path, SYSTEM_CON)
		}
		return nil
	})
}

// RestoreCon restores the SELinux context for specified paths
func RestoreCon() error {

	if err := lsetFileCon(apd, ADB_CON); err != nil {
		return err
	}
	return restoreSysConIfUnlabeled(moduleDir)
}
