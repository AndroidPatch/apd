package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// getprop sys.boot_completed
const (
	bind_mount_file = "/data/adb/.bind_mount_enable"
	temp_dir_legacy = "/sbin"
	temp_dir        = "/debug_ramdisk"
)

func ensureBootCompleted() error {
	// 检查系统启动是否完成的逻辑

	value, err := getprop("sys.boot_completed")

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	if value == "1" {
		return nil
	} else {
		return errors.New("System is loading")
	}

}
func getEnv(key string) (string, bool) {
	value, exists := os.LookupEnv(key)
	return value, exists
}
func getprop(prop string) (string, error) {
	// 执行 getprop 命令
	cmd := exec.Command("getprop", prop)

	// 获取命令输出
	output, err := cmd.CombinedOutput() // 使用 CombinedOutput 获取 stdout 和 stderr
	if err != nil {
		return "", fmt.Errorf("error running getprop: %w, output: %s", err, string(output))
	}

	// 返回去除换行符的输出
	return strings.TrimSpace(string(output)), nil
}
func ensureCleanDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		log.Printf("ensureCleanDir: %s exists, removing it", dir)
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return os.MkdirAll(dir, 0755)
}

func ensureFileExists(filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}
func ensureDirExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0700)
	}
	return nil
}
func ensureBinary(path string) error {
	return os.Chmod(path, 0755)
}
func isSafeMode(superkey *string) bool {
	safemode, err := getprop("persist.sys.safemode")
	if err == nil && safemode == "1" {
		log.Printf("safemode: true")
		return true
	}
	log.Printf("safemode: false")
	if superkey != nil {
		// 处理 superkey
		return false // 处理逻辑未实现
	}
	return false
}
func isOverlayFSSupported() (bool, error) {
	file, err := os.Open("/proc/filesystems")
	if err != nil {
		return false, fmt.Errorf("failed to open /proc/filesystems: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == "overlay" {
			return true, nil
		}
	}
	return false, scanner.Err()
}
func shouldEnableOverlay() bool {
	bindMountExists := fileExists(bind_mount_file)
	overlaySupported, _ := isOverlayFSSupported()
	return !bindMountExists && overlaySupported
}
func fileExists(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}
func getTmpPath() string {
	if fileExists(temp_dir_legacy) {
		return temp_dir_legacy
	}
	if fileExists(temp_dir) {
		return temp_dir
	}
	return ""
}
func switchCgroups() error {
	pid := os.Getpid() // 获取当前进程 ID

	// 切换到各个 cgroup
	if err := switchCgroup("/acct", pid); err != nil {
		return err
	}
	if err := switchCgroup("/dev/cg2_bpf", pid); err != nil {
		return err
	}
	if err := switchCgroup("/sys/fs/cgroup", pid); err != nil {
		return err
	}

	// 检查 ro.config.per_app_memcg 属性
	if prop, _ := getprop("ro.config.per_app_memcg"); prop == "false" {
		return switchCgroup("/dev/memcg/apps", pid)
	}

	return nil

}
func switchCgroup(grp string, pid int) error {
	path := filepath.Join(grp, "cgroup.procs")

	// 检查路径是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // 如果路径不存在，直接返回
	}

	// 以附加模式打开文件
	fp, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cgroup.procs: %w", err)
	}
	defer fp.Close()

	// 将进程 ID 写入文件
	if _, err := fmt.Fprintln(fp, pid); err != nil {
		return fmt.Errorf("failed to write pid to cgroup.procs: %w", err)
	}

	return nil
}
func switchMntNs(pid int) error {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	// 检查路径是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("mount namespace for PID %d does not exist", pid)
	}

	// 使用 setns 切换挂载命名空间
	cmd := exec.Command("setns", path, "0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to switch mount namespace: %w", err)
	}

	// 恢复当前工作目录
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	if err := os.Chdir(currentDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}

	return nil
}
func unshareMntNs() error {
	// 使用 unshare 创建新的挂载命名空间
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace failed: %w", err)
	}
	return nil
}
func Umask(mask uint32) {
	// 使用 unix.Unmask 设置 umask
	unix.Umask(int(mask))
}

func HasMagisk() bool {
	cmd := exec.Command("which", "magisk")
	err := cmd.Run()
	return err == nil
}
func mountImage(imagePath string, mountPoint string) error {
	cmd := exec.Command("mount", imagePath, mountPoint)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to mount image: %w", err)
	}
	return nil
}
