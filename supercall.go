package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	__NR_SUPERCALL         = 45     // 假设的系统调用编号，需根据内核实际定义
	SUPERCALL_SU           = 0x1010 // 假设的命令类型
	SUPERCALL_SCONTEXT_LEN = 256    // 安全上下文的长度
)

// SuProfile 定义结构体
type SuProfile struct {
	Uid      int32
	ToUid    int32
	Scontext [SUPERCALL_SCONTEXT_LEN]byte
}

// 测试函数
func test(key string) {
	var profile SuProfile
	profile.Uid = 1000                         // 当前用户 UID
	profile.ToUid = 2000                       // 目标用户 UID
	copy(profile.Scontext[:], "untrusted_app") // 填充安全上下文

	// 调用系统调用
	result := supercall(key, unsafe.Pointer(&profile))

	// 打印结果
	fmt.Printf("Result: %d\n", result)
}

// Supercall 实现
func supercall(key string, profilePtr unsafe.Pointer) int64 {
	if len(key) == 0 {
		// 返回 EINVAL 的负值
		return -int64(syscall.EINVAL)
	}

	// 将 Go 字符串转换为 C 字符串
	cKey := []byte(key + "\x00") // 手动添加 null 终止符
	keyPtr := unsafe.Pointer(&cKey[0])

	// 执行系统调用
	ret, _, errno := syscall.RawSyscall(
		uintptr(__NR_SUPERCALL),
		uintptr(keyPtr),
		uintptr(SUPERCALL_SU),
		uintptr(profilePtr), // 使用传入的 profilePtr
	)

	// 如果有错误，返回负的 errno
	if errno != 0 {
		return int64(-errno)
	}

	return int64(ret)
}
