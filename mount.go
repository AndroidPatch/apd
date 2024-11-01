package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func fsopen(fstype string, flags int) (int, error) {
	fd, err := unix.Open(fstype, unix.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func fsconfigCreate(fd int) error {
	_, _, errno := unix.Syscall(unix.SYS_FSCONFIG, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func moveMount(src, dest string) error {
	srcFd, err := unix.Open(src, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(srcFd)

	_, _, errno := unix.Syscall(unix.SYS_MOVE_MOUNT, uintptr(srcFd), uintptr(0), uintptr(0))
	if errno != 0 {
		return errno
	}
	return nil
}
func mountDevpts(dest string) error {
	err := unix.Mkdir(dest, 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}

	_, _, errno := unix.Syscall(unix.SYS_MOUNT, uintptr(unsafe.Pointer(&[]byte("devpts")[0])), uintptr(unsafe.Pointer(&[]byte(dest)[0])), uintptr(0))
	if errno != 0 {
		return errno
	}
	return nil
}
func mountTmpfs(dest string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dest, err)
	}

	// 挂载 tmpfs
	if err := unix.Mount("tmpfs", dest, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("failed to mount tmpfs on %s: %w", dest, err)
	}

	// 可选：挂载 devpts
	ptsDir := fmt.Sprintf("%s/pts", dest)
	if err := os.MkdirAll(ptsDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", ptsDir, err)
	}

	if err := unix.Mount("devpts", ptsDir, "devpts", 0, ""); err != nil {
		return fmt.Errorf("failed to mount devpts on %s: %w", ptsDir, err)
	}

	return nil
}
