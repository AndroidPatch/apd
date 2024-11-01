package main

/*
#cgo CFLAGS: -I/path/to/headers
#cgo LDFLAGS: -L/path/to/libs -llibname
#include <sys/types.h>
#include <sys/resource.h>
*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Constants
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
	SUPERCALL_SCONTEXT_LEN    = 96 // Adjust size as needed
)

// SuProfile structure
type SuProfile struct {
	UID      int32
	ToUID    int32
	SContext [SUPERCALL_SCONTEXT_LEN]byte
}

// Combine version and command into a single integer
func verAndCmd(cmd int64) int64 {
	versionCode := ((MAJOR << 16) + (MINOR << 8) + PATCH)
	return (int64(versionCode) << 32) | (0x1158 << 16) | (cmd & 0xFFFF)
}

// Call system call with provided arguments
func syscallSupercall(key *C.char, cmd int64, args ...interface{}) int64 {
	ret, _, errno := syscall.Syscall(__NR_SUPERCALL, uintptr(unsafe.Pointer(key)), uintptr(verAndCmd(cmd)), uintptr(unsafe.Pointer(&args)))
	if ret < 0 {
		return -errno
	}
	return ret
}

// Handle SU authorization
func sc_su(key *C.char, profile *SuProfile) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU, profile)
}

// Revoke UID
func sc_SuRevokeUid(key *C.char, uid uint32) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU_REVOKE_UID, uid)
}

// Grant UID
func sc_SuGrantUid(key *C.char, profile *SuProfile) int64 {
	if key == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_SU_GRANT_UID, profile)
}

// Log message to kernel
func sc_Klog(key *C.char, msg *C.char) int64 {
	if key == nil || msg == nil {
		return syscall.EINVAL
	}
	return syscallSupercall(key, SUPERCALL_KLOG, msg)
}

// Get Kernel Patch version
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

// Get Kernel version
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

// Initialize and load SU path from file
func InitLoadSUPath(superkey *C.char) {
	suPathFile := "/data/adb/ap/su_path"

	// Read SU path file
	suPath, err := ioutil.ReadFile(suPathFile)
	if err != nil {
		fmt.Printf("Failed to read su_path file: %v\n", err)
		return
	}

	// Trim whitespace
	suPathStr := strings.TrimSpace(string(suPath))

	// Convert path to C string
	suPathCStr := C.CString(suPathStr)
	defer C.free(unsafe.Pointer(suPathCStr))

	// Set SU path
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

// Reset SU path
func scSuResetPath(key *C.char, path *C.char) int64 {
	if key == nil || path == nil {
		return syscall.EINVAL
	}

	// Execute system call
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

// Set environment variable
func setEnvVar(key string, value string) error {
	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC)) // Ensure memory is freed

	valueC := C.CString(value)
	defer C.free(unsafe.Pointer(valueC)) // Ensure memory is freed

	// Set environment variable using syscall
	if err := syscall.Setenv(key, value); err != nil {
		return err
	}

	return nil
}

// Handle privilege APD profile
func privilegeAPDProfile(superkey *string) {
	allAllowCtx := "u:r:magisk:s0"
	profile := SuProfile{
		UID:   int32(os.Getpid()), // Get current process PID
		ToUID: 0,
	}
	copy(profile.SContext[:], []byte(allAllowCtx))

	if superkey != nil {
		key := *superkey
		result := sc_su(key, &profile) // Call corresponding system call
		log.Printf("[privilege_apd_profile] result = %d", result)
	}
}

// Allow UIDs
func scSuAllowUIDs(key string, buf []uint32) int64 {
	if key == "" {
		return -unix.EINVAL // Return invalid parameter error
	}
	if len(buf) == 0 {
		return -unix.EINVAL // Return invalid parameter error
	}

	keyCStr := unix.BytePtrFromString(key)
	bufPtr := unsafe.Pointer(&buf[0]) // Get pointer to buf

	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // System call number
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_LIST)),
		uintptr(bufPtr),
		uintptr(len(buf)), // Length of buf
	)

	if errno != 0 {
		return -int64(errno) // Return error code
	}
	return ret // Return system call return value
}

// Get number of UIDs
func scSuUidNums(key string) int64 {
	if key == "" {
		return -unix.EINVAL // Return invalid parameter error
	}

	keyCStr := unix.BytePtrFromString(key)

	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // System call number
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_NUMS)),
		0, // No additional parameters needed
	)

	if errno != 0 {
		return -int64(errno) // Return error code
	}
	return ret // Return system call return value
}

// Get safe mode status
func scSuGetSafemode(key string) int64 {
	if key == "" {
		// Log warning: super key is null, inform we are not in safe mode
		log.Println("[scSuGetSafemode] null superkey, tell apd we are not in safemode!")
		return 0
	}

	keyCStr := unix.BytePtrFromString(key)

	// Execute system call
	ret, _, errno := unix.Syscall(
		__NR_SUPERCALL, // System call number
		uintptr(unsafe.Pointer(keyCStr)),
		uintptr(verAndCmd(SUPERCALL_SU_GET_SAFEMODE)),
		0, // No additional parameters needed
	)

	if errno != 0 {
		log.Printf("[scSuGetSafemode] syscall error: %v", errno)
		return -int64(errno) // Return error code
	}

	return ret // Return system call return value
}

// Set application module exclusion
func scSetApModExclude(key string, uid int64, exclude int32) int64 {
	return scKstorageWrite(
		key,
		KSTORAGE_EXCLUDE_LIST_GROUP,
		uid,
		unsafe.Pointer(&exclude), // Pointer to exclude
		0,
		int32(unsafe.Sizeof(exclude)), // Size of exclude
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
