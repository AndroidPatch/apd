package main

import (
	"C"
	"syscall"
	"unsafe"
)
import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	MAJOR          = 0
	MINOR          = 11
	PATCH          = 1
	__NR_SUPERCALL = 45

	SUPERCALL_KLOG            = 0x1004
	SUPERCALL_KERNELPATCH_VER = 0x1008
	SUPERCALL_KERNEL_VER      = 0x1009
	SUPERCALL_SU              = 0x1010
	SUPERCALL_KSTORAGE_WRITE  = 0x1041
	SUPERCALL_SU_GRANT_UID    = 0x1100
	SUPERCALL_SU_REVOKE_UID   = 0x1101
	SUPERCALL_SU_NUMS         = 0x1102
	SUPERCALL_SU_LIST         = 0x1103
	SUPERCALL_SU_RESET_PATH   = 0x1111
	SUPERCALL_SU_GET_SAFEMODE = 0x1112
	SUPERCALL_SCONTEXT_LEN    = 96 // 根据需要调整大小
)

type SuProfile struct {
	UID      int32
	ToUID    int32
	SContext [SUPERCALL_SCONTEXT_LEN]byte
}

// 将 Rust 的 version 和 command 组合函数转换为 Go
func verAndCmd(cmd int64) int64 {
	versionCode := ((MAJOR << 16) + (MINOR << 8) + PATCH)
	return (int64(versionCode) << 32) | (0x1158 << 16) | (cmd & 0xFFFF)
}

// 调用系统调用
func syscallSupercall(key *C.char, cmd int64, args ...interface{}) int64 {
	ret, _, errno := syscall.Syscall(__NR_SUPERCALL, uintptr(unsafe.Pointer(key)), uintptr(verAndCmd(cmd)), uintptr(unsafe.Pointer(&args)))
	if ret < 0 {
		return -errno
	}
	return ret
}

// 处理 SU 授权
func sc_su(key *C.char, profile *SuProfile) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU, profile)
}

// 撤销 UID
func sc_SuRevokeUid(key *C.char, uid uint32) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU_REVOKE_UID, uid)
}

// 授权 UID
func sc_SuGrantUid(key *C.char, profile *SuProfile) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU_GRANT_UID, profile)
}

// 记录日志到内核
func sc_Klog(key *C.char, msg *C.char) int64 {
	if key == nil || msg == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_KLOG, msg)
}

// 获取 Kernel Patch 版本
func scKpVer(key *C.char) (uint32, error) {
	if key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	ret := syscallSupercall(key, SUPERCALL_KERNELPATCH_VER)
	if ret < 0 {
		return 0, fmt.Errorf("syscall error: %d", ret)
	}
	return uint32(ret), nil
}

// 获取 Kernel 版本
func scKVer(key *C.char) (uint32, error) {
	if key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	ret := syscallSupercall(key, SUPERCALL_KERNEL_VER)
	if ret < 0 {
		return 0, fmt.Errorf("syscall error: %d", ret)
	}
	return uint32(ret), nil
}
func initLoadSuPath(superkey *C.char) {
	suPathFile := "/data/adb/ap/su_path"

	// 读取 su_path 文件
	suPath, err := ioutil.ReadFile(suPathFile)
	if err != nil {
		fmt.Printf("Failed to read su_path file: %v\n", err)
		return
	}

	// 去除换行符
	suPathStr := strings.TrimSpace(string(suPath))

	// 将路径转换为 C 字符串
	suPathCStr := C.CString(suPathStr)
	defer C.free(unsafe.Pointer(suPathCStr))

	// 设置 SU 路径
	if superkey != nil {
		result := scSuResetPath(superkey, suPathCStr)
		if result == 0 {
			fmt.Println("suPath loaded successfully")
		} else {
			fmt.Printf("Failed to load su path, error code: %d\n", result)
		}
	} else {
		fmt.Println("Superkey is None, skipping...")
	}
}
func scSuResetPath(key *C.char, path *C.char) int64 {
	if key == nil || path == nil {
		return syscall.EINVAL
	}

	// 执行系统调用
	result, _, errno := syscall.Syscall(
		__NR_SUPERCALL,
		uintptr(unsafe.Pointer(key)),
		uintptr(SUPERCALL_SU_RESET_PATH),
		uintptr(unsafe.Pointer(path)),
	)

	if errno != 0 {
		return int64(errno)
	}
	return int64(result)
}
func setEnvVar(key string, value string) error {
	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC)) // 确保释放内存

	valueC := C.CString(value)
	defer C.free(unsafe.Pointer(valueC)) // 确保释放内存

	// 使用 syscall 设置环境变量
	if err := syscall.Setenv(key, value); err != nil {
		return err
	}

	return nil
}
func privilegeAPDProfile(superkey *string) {
	allAllowCtx := "u:r:magisk:s0"
	profile := SuProfile{
		UID:   int32(os.Getpid()), // 获取当前进程的 PID
		ToUID: 0,
	}
	copy(profile.SContext[:], []byte(allAllowCtx))

	if superkey != nil {
		key := *superkey
		result := sc_su(key, &profile) // 调用相应的系统调用
		log.Printf("[privilege_apd_profile] result = %d", result)
	}
}
func scSuAllowUIDs(key string, buf []uint32) int64 {
	if key == "" {
		return -unix.EINVAL // 返回无效参数错误
	}
	if len(buf) == 0 {
		return -unix.EINVAL // 返回无效参数错误
	}

	keyCStr := unix.BytePtrFromString(key)
	bufPtr := unsafe.Pointer(&buf[0]) // 获取 buf 的指针

	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // 系统调用号
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_LIST)),
		uintptr(bufPtr),
		uintptr(len(buf)), // buf 的长度
	)

	if errno != 0 {
		return -int64(errno) // 返回错误代码
	}
	return ret // 返回系统调用的返回值
}
func scSuUidNums(key string) int64 {
	if key == "" {
		return -unix.EINVAL // 返回无效参数错误
	}

	keyCStr := unix.BytePtrFromString(key)

	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // 系统调用号
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_NUMS)),
		0, // 不需要额外参数
	)

	if errno != 0 {
		return -int64(errno) // 返回错误代码
	}
	return ret // 返回系统调用的返回值
}
func scSuGetSafemode(key string) int64 {
	if key == "" {
		// 日志记录：超密钥为空，告知不在安全模式
		logWarn("[scSuGetSafemode] null superkey, tell apd we are not in safemode!")
		return 0
	}

	keyCStr := unix.BytePtrFromString(key)

	// 执行系统调用
	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // 系统调用号
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_GET_SAFEMODE)),
		0, // 不需要额外参数
	)

	if errno != 0 {
		logWarn("[scSuGetSafemode] syscall error: %v", errno)
		return -int64(errno) // 返回错误代码
	}

	return ret // 返回系统调用的返回值
}
func scSetApModExclude(key string, uid int64, exclude int32) int64 {
	return scKstorageWrite(
		key,
		KSTORAGE_EXCLUDE_LIST_GROUP,
		uid,
		unsafe.Pointer(&exclude), // 指向 exclude 的指针
		0,
		int32(unsafe.Sizeof(exclude)), // exclude 的大小
	)
}

// scKstorageWrite 进行 kstorage 写入（示例实现）
func scKstorageWrite(key string, gid int32, did int64, data unsafe.Pointer, offset int32, dlen int32) int64 {
	if key == "" {
		return -unix.EINVAL // 返回无效参数错误
	}

	keyCStr := unix.BytePtrFromString(key)

	// 执行系统调用
	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL,
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_KSTORAGE_WRITE)),
		uintptr(gid),
		uintptr(did),
		data,
		((int64(offset) << 32) | int64(dlen)), // offset 和 dlen 合并为一个参数
	)

	if errno != 0 {
		logWarn("[scKstorageWrite] syscall error: %v", errno)
		return -int64(errno) // 返回错误代码
	}

	return ret // 返回系统调用的返回值
}
