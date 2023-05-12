package main

import (
	//"bytes"
	"bufio"
	//"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	//"io/ioutil"
	"log"
	"os"
	//"path"
	//"path/filepath"
	"regexp"
	"runtime"
	"strings"
	//"time"
)

const (
	LinuxResultsPath = "/var/log/osquery/osqueryd.results.log"
	MacOSResultsPath = "/var/log/osquery/"
)

var (
	l                     = log.New(os.Stderr, "telemcat ", log.LstdFlags)
	gVerbose = false
	gTelemetryOutputFile  = os.Stdout

	gValidateState        = ExtractState{}
	gExtractBeginTimestamp       = uint64(0)
	gExtractEndTimestamp         = uint64(0)
	gExtractShellPid      = uint64(0)
	gTotalMessages        = uint64(0)

	// {"name":"file_events","host
	gRxQueryName = regexp.MustCompile(`^."name":"([\w-_\d]+).*"numerics":([\w\d]+)`)
	// sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash
	gRxGoArtStage = regexp.MustCompile(`sh /tmp/(artwork-T[\w-_\.\d]+)/goart-(T[\d\._]+)-(\w+)`)

)
var flagTelemPath string
var flagExtractAndValidate string
var flagAtomicTempDir string
var flagResultsPath string
var flagVerbose bool
var flagDurationSeconds uint
var flagUnbatch bool

func init() {
	flag.StringVar(&flagExtractAndValidate, "validate", "", "extract events for specific atomic test and validate using criteria in csv")
	flag.StringVar(&flagAtomicTempDir, "atomictemp", "", "path of temp directory used by atomic runner for test. Used to locate shell process for begin/end")
	flag.StringVar(&flagResultsPath, "resultsdir", "", "path to write results in validate mode")
	flag.BoolVar(&gVerbose, "verbose", false, "if true, logs more debug info")

	flag.UintVar(&flagDurationSeconds, "duration", 0, "runtime. zero means run until quit") // compat
	flag.BoolVar(&flagUnbatch, "unbatch", false, "if true, breaks batched events into individuals") // compat
}


func ParseEvent(rawJsonString string) (*EventWrapper, error) {
	retval := &EventWrapper{}

	a := gRxQueryName.FindStringSubmatch(rawJsonString)
	if len(a) < 3 {
		return retval, errors.New("unable to determine query name: " + rawJsonString[0:64])
	}
	retval.TableName = a[1]
	hasNumerics := false
	if strings.ToLower(a[2]) == "true" {
		hasNumerics = true
	}
	retval.RawJsonStr = rawJsonString

	//fmt.Println("table name:",retval.TableName, a[2])

	if !strings.HasSuffix(retval.TableName, "_events") {
		if gVerbose {
			fmt.Println("table name:",retval.TableName,"XXX")
		}
		return nil, nil
	}
	var err error

	switch retval.TableName {
	case "file_events":
		if hasNumerics {
			msg := &INotifyFileEvent{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.INotifyFileMsg = msg
		} else {
			msg := &INotifyFileEventStr{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.INotifyFileMsg = msg.ToTyped()
		}
		//fmt.Println(*retval.INotifyFileMsg)
	case "bpf_process_events":
		if hasNumerics {
			msg := &BpfProcessEvent{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.BpfProcessMsg = msg

		} else {
			msg := &BpfProcessEventStr{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.BpfProcessMsg = msg.ToTyped()
		}
		//fmt.Println(*retval.BpfProcessMsg)
	default:
		if gVerbose {
			fmt.Println("Unsupported event table:", retval.TableName)
		}
		return nil, nil
	}

	return retval, nil
}

func IsGoArtStage(cmdline string, ts uint64) bool {
	a := gRxGoArtStage.FindStringSubmatch(cmdline)
	if len(a) > 3 {
		folder := a[1]
		technique := a[2]
		stageName := a[3]
		if gVerbose {
			fmt.Println("Found stage", stageName,"for", technique,"folder:",folder)
		}
		if "test" == stageName {
			// is this the target test?
			if gValidateState.TestData.Technique == technique {
				tsttok := fmt.Sprintf("%s_%d", gValidateState.TestData.Technique, gValidateState.TestData.TestIndex)
				fmt.Println("contains check", folder, tsttok)
				if strings.Contains(folder, tsttok) {
					gExtractBeginTimestamp = ts
				}
			}
		} else if 0 != gExtractBeginTimestamp {
			gExtractEndTimestamp = ts
		}
		return true
	}
	return false
}

func IncludeEvent(rawJsonString string) {
	gTotalMessages += 1
	fmt.Fprintln(gTelemetryOutputFile, rawJsonString)
	fmt.Println("Added", rawJsonString)
}

func HandleEvent(evt *EventWrapper) {
	switch evt.TableName {
	case "bpf_process_events":
		if IsGoArtStage(evt.BpfProcessMsg.Columns.Cmdline, evt.BpfProcessMsg.UnixTime) {
			return
		}
		if 0 != gExtractBeginTimestamp && 0 == gExtractEndTimestamp {
			IncludeEvent(evt.RawJsonStr)
		}
	default:
	}

}

func processFile(path string) {
    file, err := os.Open(path)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
    	line := scanner.Text()
        //fmt.Println(line)

		evt,err := ParseEvent(line)
		if err != nil {
			fmt.Println(err)		
		}
		if evt == nil {
			continue
		}
		//fmt.Println(evt)
		HandleEvent(evt)

        //break
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("Error:", err)
    }
}

func main() {
	flag.Parse()

	files := flag.Args()

	if flagTelemPath == "" {
		switch runtime.GOOS {
		case "darwin":
			flagTelemPath = MacOSResultsPath
		case "linux":
			flagTelemPath = LinuxResultsPath
		default:
			fmt.Println("no default telempath for ", runtime.GOOS)
			os.Exit(1)
		}
	}

/*
	//line := `{"name":"file_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:45 2023 UTC","unixTime":1683584145,"epoch":0,"counter":105,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},"columns":{"action":"CREATED","atime":"","category":"custom_category","ctime":"","gid":"","hashed":"0","inode":"","md5":"","mode":"","mtime":"","sha1":"","sha256":"","size":"","target_path":"/tmp/passwd.zip","time":"1683584089","transaction_id":"0","uid":""},"action":"added"}`
	//line := `{"name":"bpf_process_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:00 2023 UTC","unixTime":1683584100,"epoch":0,"counter":57,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},"columns":{"cid":"10198","cmdline":"/usr/bin/python3 -c 'from zipfile import ZipFile; ZipFile('/tmp/passwd.zip', mode='w').write('/etc/passwd')'","cwd":"/home/amscwx","duration":"132369","exit_code":"0","gid":"0","ntime":"92306415722842","parent":"20478","path":"/usr/bin/python3","pid":"20481","probe_error":"0","syscall":"exec","tid":"20481","uid":"1002"},"action":"added"}`
	line := `{"name":"bpf_process_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:00 2023 UTC","unixTime":1683584100,"epoch":0,"counter":57,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},"columns":{"cid":"10198","cmdline":"bash /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash","cwd":"/home/amscwx","duration":"130942","exit_code":"0","gid":"0","ntime":"92306409329558","parent":"20468","path":"/usr/bin/bash","pid":"20478","probe_error":"0","syscall":"exec","tid":"20478","uid":"1002"},"action":"added"}`

	evt,err := ParseEvent(line)
	if err != nil {
		fmt.Println(err)		
	}
	if evt == nil {
		return
	}
	fmt.Println(evt)
	HandleEvent(evt)
*/
	if flagExtractAndValidate != "" {
		var err error
		data := []byte{}

		if flagExtractAndValidate == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(flagExtractAndValidate)
		}

		if err != nil {
			fmt.Println("IO error",err," file:", flagExtractAndValidate)
			os.Exit(2)
		}
		
		err = json.Unmarshal(data, &gValidateState.TestData)
		if err != nil {
			fmt.Println("Error parsing validation criteria JSON",err)
			os.Exit(2)
		}
		fmt.Println(gValidateState.TestData)

		outpath := flagResultsPath + "/telemetry.json"
		gTelemetryOutputFile,err = os.OpenFile(outpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to create outfile",outpath, err)
			os.Exit(2)
		}
	}
	defer gTelemetryOutputFile.Close()

	// read in osqueryd.results file

	if len(files) > 0 {
		for _,f := range files {
			processFile(f)
		}
	} else {
		// use -inpath , which has system default

		info, err := os.Stat(flagTelemPath)
		if os.IsNotExist(err) {
			fmt.Println("file does not exist", flagTelemPath)
			os.Exit(2)
		} else if err != nil {
			fmt.Println("IO error",err," file:", flagTelemPath)
			os.Exit(2)
		}

		if info.IsDir() {
			fmt.Println("ERROR: input file is a directory", flagTelemPath)
			return
		} else {
			processFile(flagTelemPath)
		}
	}

	// output

	if flagExtractAndValidate != "" {
		gValidateState.StartTime = gExtractBeginTimestamp
		gValidateState.EndTime = gExtractEndTimestamp
		gValidateState.TotalEvents = gTotalMessages

		// TODO: EvaluateProcessCorrelations()

		// output summary

		jb, err := json.MarshalIndent(gValidateState,"","  ")
		if err != nil {
			l.Println("failed to encode validation state json", err)
		} else {

			outPath := flagResultsPath + "/validate_summary.json"
			err = os.WriteFile(outPath, jb, 0644)
			if err != nil {
				fmt.Println("ERROR: unable to write file", outPath, err)
			}
		}

		// output match string
		s := GetTelemTypes(& gValidateState.TestData)
		outPath := flagResultsPath + "/match_string.txt"
		err = os.WriteFile(outPath, []byte(s), 0644)
		if err != nil {
			fmt.Println("ERROR: unable to write file", outPath, err)
		}

		// set exit code if telemetry missing some expected items

		if gValidateState.Coverage == 1.0 {
			os.Exit(int(StatusValidateSuccess))
		} else if gValidateState.Coverage == 0.0 {
			os.Exit(int(StatusValidateFail))
		}
		os.Exit(int(StatusValidatePartial))
	}

}
