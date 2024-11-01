package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func setIdentity(uid, gid int) error {
	// 设置 GID
	if err := syscall.Setgid(int(gid)); err != nil {
		return fmt.Errorf("failed to set GID: %v", err)
	}

	// 设置 UID
	if err := syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("failed to set UID: %v", err)
	}

	return nil
}
func create_root_shell() error {
	args := os.Args[1:]

	// 解析命令行参数
	var command []string
	for i, arg := range args {
		if arg == "-c" && i+1 < len(args) {
			command = append(command, args[i:]...)
			break
		}
	}

	if len(command) == 0 {
		command = args
	}

	// 检查是否有帮助和版本标志
	for _, arg := range command {
		if arg == "-h" {
			printUsage()
			return nil
		}
		if arg == "-v" {
			fmt.Println("Version: 1.0")
			return nil
		}
		if arg == "-V" {
			fmt.Println("Version Code: 1")
			return nil
		}
	}

	// 处理用户身份
	var uid, gid int
	if len(args) > 0 {
		userInfo, err := user.Lookup(args[0])
		if err == nil {
			uid, _ = strconv.Atoi(userInfo.Uid) // 转换为 int
			gid, _ = strconv.Atoi(userInfo.Gid) // 转换为 int
		}
	}

	// 设置环境变量
	if err := os.Setenv("HOME", os.Getenv("HOME")); err != nil {
		return err
	}

	// 执行命令
	shell := "/bin/sh" // 可以根据需要设置
	if len(command) > 0 {
		shell = command[0]
		command = command[1:] // 剩余的参数
	}
	if err := setIdentity(uid, gid); err != nil {
		return err
	}
	cmd := exec.Command(shell, command...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	_, _ = syscall.ForkExec("/bin/sh", []string{"sh"}, &syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Setpgid: true,
		},
	})
	//cmd.Env = os.Environ()
	//if _, err := cmd.Output(); err != nil {
	//	return err
	//}

	return nil
}

func printUsage() {
	fmt.Println("Usage: command [options]")
	// 添加更多帮助信息
}
