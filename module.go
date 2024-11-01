package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed installer.sh
var installer string

const (
	disableFileName = "disable"
	updateFileName  = "update"
	removeFileName  = "remove"
	moduleWebDir    = "web"
	moduleActionSh  = "action.sh"
	adbDir          = "/data/adb/"
	workingDir      = "/data/adb/ap/"
	binaryDir       = "/data/adb/ap/bin/"
	moduleDir       = "/data/adb/modules/"
	moduleupdateDir = "/data/adb/modules_update/"
	busybox         = "/data/adb/ap/bin/busybox"
	magiskpolicy    = "/data/adb/ap/bin/magiskpolicy"
	resetprop       = "/data/adb/ap/bin/resetprop"
	apd             = "/data/adb/apd"
	ap_log          = "/data/adb/ap/log/"
	tmp_img         = "/data/adb/ap/tmp_img.img"
)

func loadSystemProp() error {
	return foreachModule(true, func(module string) error {
		systemProp := filepath.Join(module, "system.prop")
		if _, err := os.Stat(systemProp); os.IsNotExist(err) {
			return nil // 如果文件不存在，则跳过
		}

		log.Printf("load %s system.prop", module)

		cmd := exec.Command(resetprop, "-n", "--file", systemProp)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to exec %s: %w", systemProp, err)
		}

		return nil
	})
}
func loadSEPolicyRule() error {
	return foreachModule(true, func(module string) error {
		ruleFile := filepath.Join(module, "sepolicy.rule")
		if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
			return nil // 如果文件不存在，则跳过
		}

		log.Printf("load policy: %s", ruleFile)

		cmd := exec.Command(magiskpolicy, "--live", "--apply", ruleFile)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to exec %s: %w", ruleFile, err)
		}

		return nil

	})

}
func pruneModules() error {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		modulePath := filepath.Join(moduleDir, entry.Name())

		// 删除更新文件
		if err := os.Remove(filepath.Join(modulePath, updateFileName)); err != nil {
			// 忽略错误
		}

		// 检查是否存在移除文件
		removeFilePath := filepath.Join(modulePath, removeFileName)
		if _, err := os.Stat(removeFilePath); os.IsNotExist(err) {
			continue
		}

		log.Printf("remove module: %s", modulePath)

		// 执行卸载脚本
		uninstaller := filepath.Join(modulePath, "uninstall.sh")
		if _, err := os.Stat(uninstaller); !os.IsNotExist(err) {
			if execErr := execScript(uninstaller, true); execErr != nil {
				log.Printf("failed to exec uninstaller: %v", execErr)
			}
		}

		// 删除模块目录
		if err := os.RemoveAll(modulePath); err != nil {
			log.Printf("failed to remove %s: %v", modulePath, err)
		}

		// 删除更新临时目录
		updatedPath := filepath.Join(moduleupdateDir, entry.Name())
		if err := os.RemoveAll(updatedPath); err != nil {
			log.Printf("failed to remove %s: %v", updatedPath, err)
		}
	}

	return nil
}

func foreachModule(active bool, fn func(module string) error) error {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {

			if active {
				disableFilePath := filepath.Join(moduleDir, entry.Name(), disableFileName)
				if _, err := os.Stat(disableFilePath); err == nil {
					// Disable file exists, skip this module
					continue
				}
			}
			modulePath := filepath.Join(moduleDir, entry.Name())
			if err := fn(modulePath); err != nil {
				return err
			}
		}
	}
	return nil
}
func execCommonScripts(dir string, wait bool) error {
	scriptDir := filepath.Join(adbDir, dir)

	// 检查目录是否存在
	if _, err := os.Stat(scriptDir); os.IsNotExist(err) {
		fmt.Sprintf("%s not exists, skip", scriptDir)
		return nil
	}

	entries, err := os.ReadDir(scriptDir)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", scriptDir, err)
	}

	for _, entry := range entries {
		path := filepath.Join(scriptDir, entry.Name())

		if !isExecutable(path) {
			fmt.Sprintf("%s is not executable, skip", path)
			continue
		}

		if err := execScript(path, wait); err != nil {
			return err
		}
	}

	return nil
}
func isExecutable(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.Mode().Perm()&0111 != 0 // 检查执行权限
}
func execScript(path string, wait bool) error {
	log.Printf("exec %s", path)

	// 创建命令
	cmd := exec.Command("sh", path)

	// 设置工作目录为脚本所在目录
	cmd.Dir = filepath.Dir(path)

	// 设置环境变量
	cmd.Env = os.Environ() // 继承当前环境变量
	cmd.Env = append(cmd.Env, "ASH_STANDALONE=1")
	cmd.Env = append(cmd.Env, "APATCH=true")
	cmd.Env = append(cmd.Env, fmt.Sprintf("APATCH_VER=%s", "your_version_name"))               // 替换为实际版本
	cmd.Env = append(cmd.Env, fmt.Sprintf("APATCH_VER_CODE=%s", "your_version_code"))          // 替换为实际版本代码
	cmd.Env = append(cmd.Env, fmt.Sprintf("PATH=%s:%s", os.Getenv("PATH"), "your_binary_dir")) // 替换为实际路径

	var err error
	if wait {
		_, err = cmd.Output() // 等待命令执行完成并获取输出
	} else {
		err = cmd.Start() // 启动命令但不等待
	}

	if err != nil {
		return fmt.Errorf("Failed to exec %s: %w", path, err)
	}

	return nil
}
func ExecStageScript(stage string, block bool) error {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		disableFilePath := filepath.Join(moduleDir, entry.Name(), disableFileName)
		// Check if the disable file exists
		if _, err := os.Stat(disableFilePath); err == nil {
			// Disable file exists, skip this module
			continue
		}

		scriptPath := filepath.Join(moduleDir, entry.Name(), fmt.Sprintf("%s.sh", stage))
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			// Skip if the script does not exist
			continue
		}

		if err := execScript(scriptPath, block); err != nil {
			return fmt.Errorf("failed to exec script %s: %w", scriptPath, err)
		}
	}
	return nil
}
func markUpdate() error {
	// 构造文件路径
	updateFilePath := fmt.Sprintf("%s/%s", workingDir, updateFileName)
	return ensureFileExists(updateFilePath)
}
func readModuleProp(zipPath string) (map[string]string, error) {
	prop := make(map[string]string)

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "module.prop" {
			//println(f.Name)
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					prop[key] = value
				}
			}
		}
	}
	return prop, nil
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if err := extractFile(f, dest); err != nil {
			return err
		}
	}
	return nil
}
func extractFile(f *zip.File, dest string) error {
	path := filepath.Join(dest, f.Name)

	// 检查文件名的路径，防止目录遍历
	if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("%s: illegal file path", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, 0755)
	}

	// 创建目录
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// 创建文件
	outFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	// 解压文件内容
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

func installModule(zip string) error {
	printbanner()
	if err := ensureBootCompleted(); err != nil {
		return err
	}
	if err := ensureDirExists(workingDir); err != nil {
		return fmt.Errorf("failed to create working dir: %w", err)
	}
	if err := ensureDirExists(binaryDir); err != nil {
		return fmt.Errorf("failed to create bin dir: %w", err)
	}

	moduleProp, err := readModuleProp(zip)
	if err != nil {
		return err
	}
	//fmt.Printf("Module prop: %+v\n", moduleProp)

	moduleID, ok := moduleProp["id"]
	if moduleID == "" {

		return errors.New("unable to install module")
	}
	if !ok {
		return fmt.Errorf("module id not found in module.prop")
	}

	modulesDir := filepath.Join(moduleDir, moduleID)
	//modulesUpdateDir := filepath.Join(moduleUpdateTmpDir, moduleID)

	if err := ensureDirExists(modulesDir); err != nil {
		return fmt.Errorf("failed to create module folder: %w", err)
	}

	// 解压缩模块到目标目录
	err = unzip(zip, modulesDir)
	if err != nil {
		return err
	}
	//fmt.Println(modulesUpdateDir)
	args := []string{"sh", "-c", installer}
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(busybox, args...)
	cmd.Env = os.Environ() // 复制当前环境变量
	cmd.Env = append(cmd.Env, "ASH_STANDALONE=1")
	cmd.Env = append(cmd.Env, fmt.Sprintf("PATH=%s;%s", os.Getenv("PATH"), filepath.Dir(binaryDir)))
	cmd.Env = append(cmd.Env, "APATCH=true")
	cmd.Env = append(cmd.Env, fmt.Sprintf("APATCH_VER=%s", "your_version"))
	cmd.Env = append(cmd.Env, fmt.Sprintf("APATCH_VER_CODE=%s", "10993"))
	cmd.Env = append(cmd.Env, "OUTFD=1")
	cmd.Env = append(cmd.Env, fmt.Sprintf("ZIPFILE=%s", zip))
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("error with:", err)
		fmt.Printf("stderr: %s\n", stderr.String()) // 打印错误输出
		fmt.Printf("stdout: %s\n", out.String())    // 打印错误输出
	}
	fmt.Println(out.String())
	markUpdate()
	return nil
}
func enableModule(id string, enable bool) error {
	srcModulePath := filepath.Join(moduleDir, id)
	_, err := os.Stat(srcModulePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("module: %s not found", id)
	} else if err != nil {
		return err
	}

	disablePath := filepath.Join(srcModulePath, disableFileName)
	if enable {
		if _, err := os.Stat(disablePath); err == nil {
			// 删除 disable 文件
			if err := os.Remove(disablePath); err != nil {
				return fmt.Errorf("failed to remove disable file: %s, error: %v", disablePath, err)
			}
		}
	} else {
		// 确保 disable 文件存在
		if err := ensureFileExists(disablePath); err != nil {
			return err
		}
	}
	if err := markModuleState(moduleDir, id, disableFileName, !enable); err != nil {
		return err
	}

	return nil
}

func markModuleState(moduleDir string, module string, flagFile string, createOrDelete bool) error {
	moduleStateFile := filepath.Join(moduleDir, module, flagFile)
	fmt.Println(moduleDir, module, flagFile, createOrDelete, moduleStateFile)
	if createOrDelete {
		// 创建文件
		return ensureFileExists(moduleStateFile)
	} else {
		// 删除文件
		if _, err := os.Stat(moduleStateFile); err == nil {
			// 如果文件存在，则删除
			if err := os.Remove(moduleStateFile); err != nil {
				return fmt.Errorf("failed to remove file: %s, error: %v", moduleStateFile, err)
			}
		}
		return nil
	}
}
func disableAllModulesUpdate() error {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(moduleDir, entry.Name())
		disableFlag := filepath.Join(path, disableFileName)

		// 确保文件存在
		if err := ensureFileExists(disableFlag); err != nil {
			fmt.Printf("Failed to disable module: %s: %v\n", path, err)
		}
	}
	return nil
}

func listModules() ([]map[string]string, error) {
	modules := []map[string]string{}

	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		modulePropPath := filepath.Join(moduleDir, entry.Name(), "module.prop")
		if _, err := os.Stat(modulePropPath); os.IsNotExist(err) {
			continue
		}

		file, err := os.Open(modulePropPath)
		if err != nil {
			fmt.Printf("Failed to read file: %s\n", modulePropPath)
			continue
		}
		defer file.Close()

		modulePropMap := make(map[string]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				modulePropMap[key] = value
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Failed to parse module.prop: %s\n", modulePropPath)
			continue
		}

		if id, exists := modulePropMap["id"]; !exists || id == "" {
			id := entry.Name()
			fmt.Printf("Use dir name as module id: %s\n", id)
			modulePropMap["id"] = id
		}

		// Add enabled, update, remove flags
		enabled := !fileExists(filepath.Join(moduleDir, entry.Name(), disableFileName))
		update := fileExists(filepath.Join(moduleDir, entry.Name(), updateFileName))
		remove := fileExists(filepath.Join(moduleDir, entry.Name(), removeFileName))
		web := fileExists(filepath.Join(moduleDir, entry.Name(), moduleWebDir))
		action := fileExists(filepath.Join(moduleDir, entry.Name(), moduleActionSh))

		modulePropMap["enabled"] = fmt.Sprintf("%t", enabled)
		modulePropMap["update"] = fmt.Sprintf("%t", update)
		modulePropMap["remove"] = fmt.Sprintf("%t", remove)
		modulePropMap["web"] = fmt.Sprintf("%t", web)
		modulePropMap["action"] = fmt.Sprintf("%t", action)

		modules = append(modules, modulePropMap)
	}

	return modules, nil
}
