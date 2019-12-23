package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ullaakut/nmap"
)

var hostsWOpenService []nmap.Host

var (
	nmapFile = flag.String("in", "", "an nmap xml file that you want to parse")
	outFile  = flag.String("outfile", "", "unless specified, will be nmapFileName_proto_IPs.txt")
	proto    = flag.String("proto", "", "a protocol go-netscan supports: ldap, vnc, smb(microsoft-ds), ssh, winrm")
)

func main() {
	// Parse flags
	flag.Parse()

	// Parse nmap.xml file
	if *nmapFile == "" {
		log.Println("Please specify an input file: -in")
		os.Exit(1)
	}
	if *proto == "" {
		log.Println("Please specify a protocol: -proto {ldap, vnc, smb, ssh, winrm}")
		os.Exit(1)
	}
	log.Println(*nmapFile)
	targets, err := ParseNmapService(*nmapFile, *proto)
	if err != nil {
		log.Printf("Error parsing nmap file: %v\n", err.Error())
	}

	// Write out output file w/ just IP addresses
	var outFileName string
	if *outFile != "" {
		outFileName = *outFile
	} else {
		outFileName = *proto + "_" + *nmapFile + "_IPs.txt"
	}
	log.Printf("%v", targets)
	err = WriteFile(outFileName, targets)
	if err != nil {
		log.Printf("Error writing file: %v\n", err.Error())
		os.Exit(1)
	}
	log.Printf("Wrote file: %s\n", outFileName)
	os.Exit(0)
}

func ParseNmapService(filepath, protoc string) ([]string, error) {
	var targets []string
	dataz, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("errors: %v\n", err.Error())
		return nil, err
	}
	// parse using nmap lib
	result, err := nmap.Parse(dataz)
	if err != nil {
		log.Printf("errors: %v\n", err.Error())
		return nil, err
	}
	// Create a master host list of hosts w/ open services
	for _, singHost := range result.Hosts {
		for _, sp := range singHost.Ports {
			if (sp.Status() == "open") && (sp.Service.Name == protoc) {
				hostsWOpenService = append(hostsWOpenService, singHost)
				// get addresses for these hosts
				for _, singAddress := range singHost.Addresses {
					targets = append(targets, singAddress.Addr)
				}
			}
		}
	}
	return targets, nil
}

func WriteFile(destPath string, addresses []string) error {
	absDir, err := filepath.Abs(filepath.Dir(destPath))
	if err != nil {
		return err
	}
	dirInfo, err := os.Stat(absDir)
	if err != nil {
		return err
	}
	fileData := strings.Join(addresses[:], "\n")
	err = ioutil.WriteFile(destPath, []byte(fileData), os.FileMode(dirInfo.Mode()))
	if err != nil {
		return err
	}
	return nil
}
