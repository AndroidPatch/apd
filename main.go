package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func printbanner() {
	banner := `
    _    ____       _       _     
   / \  |  _ \ __ _| |_ ___| |__  
  / _ \ | |_) / _` + "`" + ` | __/ __| '_ \ 
 / ___ \|  __/ (_| | || (__| | | |
/_/   \_\_|   \__,_|\__\___|_| |_|
   `
	fmt.Println(banner)
}
func main() {
	programName := filepath.Base(os.Args[0])
	if strings.HasSuffix(programName, "su") || strings.HasSuffix(programName, "kp") {
		if err := create_root_shell(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) < 2 {
		fmt.Println("Usage: apd module install <module-name>")
		return
	}
	args := os.Args[1:]
	superkey := "none"
	flag.StringVar(&superkey, "s", "none", "superkey")
	flag.Parse()
	//fmt.Println("key", superkey)
	if superkey != "none" {
		args = os.Args[3:]
	}
	//fmt.Println(args)
	if args[0] == "module" {
		if args[1] == "test" {
			test := args[2]
			fmt.Printf("test function: %s\n", test)

			return
		}
		if args[1] == "install" {

			modulepath := args[2]
			fmt.Printf("Installing module: %s\n", modulepath)
			installModule(modulepath)
			return
		}
		if args[1] == "list" {

			modules, err := listModules()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			// 将模块转换为JSON格式
			jsonOutput, err := json.MarshalIndent(modules, "", "  ")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println(string(jsonOutput))
			return
		}
		if args[1] == "enable" {
			if err := enableModule(args[2], true); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			return
		}
		if args[1] == "disable" {
			if err := enableModule(args[2], false); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			return
		}
		if args[1] == "disable_all_modules" {
			if err := disableAllModulesUpdate(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			return
		}

		fmt.Println("Usage: apd module install <module-name>")
		return
	}
	if args[0] == "post-fs-data" { //Trigger `post-fs-data` event
		on_postdata_fs(superkey)
	}
	if args[0] == "services" { //Trigger `services` event
		on_services(superkey)
	}
	if args[0] == "boot-completed" { //Trigger `boot-completed` event
		on_boot_completed(superkey)
	}
	if args[0] == "supercall" { //Trigger `boot-completed` event
		test(superkey)
	}
	if args[0] == "getprop" {
		value, err := getprop(args[1])
		//value, err := getprop("vendor.post_boot.parsed")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("%s: %s\n", args[1], value)

	}

}
