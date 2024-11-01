package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func execCommand(command string, args []string) error {
	cmd := exec.Command(command, args...)
	return cmd.Run()
}
func on_postdata_fs(superkey string) {
	Umask(0)

	//initLoadPackageUIDConfig(superkey)
	//initLoadSUPath(superkey)

	args := []string{"--magisk", "--live"}
	//if err := forkForResult("/data/adb/ap/bin/magiskpolicy", args, superkey); err != nil {
	//	return err
	//}
	if err := execCommand(magiskpolicy, args); err != nil {
		return
	}

	//info("Re-privilege apd profile after injecting sepolicy")
	//supercallPrivilegeAPDProfile(superkey)

	if HasMagisk() {
		//warn("Magisk detected, skip post-fs-data!")
		return
	}

	// Create log environment
	if _, err := os.Stat(ap_log); os.IsNotExist(err) {
		if err := os.Mkdir(ap_log, 0700); err != nil {
			//return fmt.Errorf("failed to create log folder: %w", err)
			return
		}
	}

	// Remove old log files
	commandString := fmt.Sprintf("rm %s*.old; for file in %s*; do mv \"$file\" \"$file.old\"; done", ap_log, ap_log)

	if err := execCommand("sh", []string{"-c", commandString}); err != nil {
		return
	}

	logcatPath := filepath.Join(ap_log, "logcat.log")

	args = []string{"nohup", "timeout", "-s", "9", "120s", "logcat", "-b", "main,system,crash", "-f", logcatPath, "logcatcher-bootlog:S", "&"}
	if err := execCommand("timeout", args); err != nil {
		return
	}

	args = []string{"nohup", "timeout", "-s", "9", "120s", "dmesg", "-w>/data/adb/log/dmesg.log", "/2>&1", "&"}
	if err := execCommand(busybox, args); err != nil {
		return
	}
	//dmesgPath := filepath.Join(ap_log, "dmesg.log")
	//bootlog, err := os.Create(dmesgPath)
	//if err != nil {
	//	return
	//}

	// Start logcat and dmesg processes
	//if err := startLogcat(logcatPath); err != nil {
	//	return err
	//}

	//if err := startDmesg(bootlog); err != nil {
	//	return err
	//}

	// Print kernel information
	//printKernelInfo("KERNELPATCH_VERSION")
	//printKernelInfo("KERNEL_VERSION")

	safeMode := isSafeMode(&superkey)

	if safeMode {
		//warn("safe mode, skip common post-fs-data.d scripts")
		if err := disableAllModulesUpdate(); err != nil {
			//warn(fmt.Sprintf("disable all modules failed: %v", err))
			fmt.Sprintf("disable all modules failed: %v", err)
		}
	} else {
		if err := execCommonScripts("post-fs-data.d", true); err != nil {
			//warn(fmt.Sprintf("exec common post-fs-data scripts failed: %v", err))
			fmt.Sprintf("exec common post-fs-data scripts failed: %v", err)
		}
	}

	moduleDir := moduleDir
	moduleUpdateFlag := filepath.Join(workingDir, updateFileName)
	if err := ensureBinary(binaryDir); err != nil {
		fmt.Errorf("binary missing: %w", err)
		return
	}

	tmpModuleImg := tmp_img
	tmpModulePath := filepath.Join(tmpModuleImg)

	if (fileExists(moduleUpdateFlag) || !fileExists(tmpModulePath)) && shouldEnableOverlay() {
		if err := ensureCleanDir(moduleDir); err != nil {
			return
		}
		//info("remove update flag")
		os.Remove(moduleUpdateFlag)

		// Prepare the image
		if err := pruneModules(); err != nil {
			return
		}
	} else if shouldEnableOverlay() {
		if err := ensureCleanDir(moduleDir); err != nil {
			return
		}
		// Mounting last time img file
		//info("- Mounting image")
		if err := mountImage(tmpModuleImg, moduleDir); err != nil {
			return
		}
	} else {
		//info("do nothing here")
	}

	if safeMode {
		//warn("safe mode, skip post-fs-data scripts and disable all modules!")
		if err := disableAllModulesUpdate(); err != nil {
			//warn(fmt.Sprintf("disable all modules failed: %v", err))
		}
		return
	}

	if err := pruneModules(); err != nil {
		fmt.Sprintf("prune modules failed: %v", err)
	}

	if err := RestoreCon(); err != nil {
		fmt.Sprintf("restorecon failed: %v", err)
	}

	if err := loadSEPolicyRule(); err != nil {
		fmt.Println("load sepolicy.rule failed")
	}

	if err := mountTmpfs(getTmpPath()); err != nil {
		fmt.Sprintf("do temp dir mount failed: %v", err)
	}

	// Execute modules post-fs-data scripts
	if err := ExecStageScript("post-fs-data", true); err != nil {
		fmt.Sprintf("exec post-fs-data scripts failed: %v", err)
	}

	// Load system.prop
	if err := loadSystemProp(); err != nil {
		fmt.Sprintf("load system.prop failed: %v", err)
	}

	//if shouldEnableOverlay() {
	//	if err := mountSystemlessly(moduleDir); err != nil {
	//		warn(fmt.Sprintf("do systemless mount failed: %v", err))
	//	}
	//} else {
	//	if err := systemlessBindMount(moduleDir); err != nil {
	//		warn(fmt.Sprintf("do systemless bind_mount failed: %v", err))
	//	}
	//}

	runStage("post-mount", &superkey, true)

	if err := os.Chdir("/"); err != nil {
		fmt.Errorf("failed to chdir to /: %w", err)
	}

	return
}
func on_services(superkey string) {

}
func on_boot_completed(superkey string) {

}
func runStage(stage string, superkey *string, block bool) {
	Umask(0)

	if HasMagisk() {
		log.Printf("Magisk detected, skip %s", stage)
		return
	}

	if isSafeMode(superkey) {
		log.Printf("safe mode, skip %s scripts", stage)
		if err := disableAllModulesUpdate(); err != nil {
			log.Printf("disable all modules failed: %v", err)
		}
		return
	}

	if err := execScript(fmt.Sprintf("%s.d", stage), block); err != nil {
		log.Printf("Failed to exec common %s scripts: %v", stage, err)
	}
	if err := ExecStageScript(stage, block); err != nil {
		log.Printf("Failed to exec %s scripts: %v", stage, err)
	}
}
