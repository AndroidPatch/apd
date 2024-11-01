package main

import (
	"bufio"
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

	// 解析命令行参数，寻找 -c 标志
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

	// 检查帮助和版本标志
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
			uid, _ = strconv.Atoi(userInfo.Uid)
			gid, _ = strconv.Atoi(userInfo.Gid)
		}
	}

	// 设置环境变量
	if err := os.Setenv("HOME", os.Getenv("HOME")); err != nil {
		return err
	}

	// 执行命令
	shell := "/bin/sh" // 默认 shell
	if len(command) > 0 {
		shell = command[0]
		command = command[1:]
	}
	if err := setIdentity(uid, gid); err != nil {
		return err
	}

	// 创建命令
	cmd := exec.Command(shell, command...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// 重定向输入输出

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("Error creating stdin pipe:", err)
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		return nil
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting command:", err)
		return nil
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()
	reader := bufio.NewReader(os.Stdin)
	for {
		//fmt.Print("Enter command: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			break
		}

		// 写入到 stdin
		_, err = stdin.Write([]byte(input))
		if err != nil {
			fmt.Println("Error writing to stdin:", err)
			break
		}
	}

	// 等待命令结束
	if err := cmd.Wait(); err != nil {
		fmt.Println("Command finished with error:", err)
	}

	return nil
}

func printUsage() {
	fmt.Println("Usage: command [options]")
	// 添加更多帮助信息
}
