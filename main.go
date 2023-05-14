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
	"os/exec"
	//"path"
	//"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	LinuxResultsPath = "/var/log/osquery/osqueryd.results.log"
	MacOSResultsPath = "/var/log/osquery/"
)

var (
	l                     = log.New(os.Stderr, "telemcat ", log.LstdFlags)
	gVerbose = false
	gTelemetryOutputFile  = os.Stdout
	gSimpleTelemetryOutputFile  = os.Stdout

	gValidateState        = ExtractState{}
	gExtractBeginTimestamp       = int64(0)
	gExtractEndTimestamp         = int64(0)
	gExtractShellPid      = uint64(0)
	gTotalMessages        = uint64(0)
	gTimeRangeStart = int64(0)
	gTimeRangeEnd = int64(0)
	gSystemStartTime = uint64(0)

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
var flagTimeRangeStr string

func init() {
	flag.StringVar(&flagExtractAndValidate, "validate", "", "extract events for specific atomic test and validate using criteria in csv")
	flag.StringVar(&flagAtomicTempDir, "atomictemp", "", "path of temp directory used by atomic runner for test. Used to locate shell process for begin/end")
	flag.StringVar(&flagResultsPath, "resultsdir", "", "path to write results in validate mode")
	flag.BoolVar(&gVerbose, "verbose", false, "if true, logs more debug info")
	flag.StringVar(&flagTimeRangeStr, "ts", "", "start,end unix timestamps")

	flag.UintVar(&flagDurationSeconds, "duration", 0, "time to wait for telemetry") // compat
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

func IsGoArtStage(cmdline string, tsNs int64) bool {
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
				fmt.Println("contains check", folder, tsttok, tsNs)
				if strings.Contains(folder, tsttok) {
					gExtractBeginTimestamp = tsNs
					gExtractEndTimestamp = 0
				}
			}
		} else if 0 != gExtractBeginTimestamp {
			gExtractEndTimestamp = tsNs
		}
		return true
	}
	return false
}

func IncludeEvent(rawJsonString string, simpleEvt *SimpleEvent) {
	gTotalMessages += 1
	fmt.Fprintln(gTelemetryOutputFile, rawJsonString)

	jb, err := json.Marshal(simpleEvt)
	if err != nil {
		fmt.Println("failed to encode EVENT json", err, simpleEvt)
	} else {
		fmt.Fprintln(gSimpleTelemetryOutputFile, string(jb))
	}

	//fmt.Println("Added", rawJsonString)
}

func GetTsFromUptime(uptimeNanos uint64) int64 {
	return int64(gSystemStartTime + uptimeNanos)
}

func InSpecifiedTimeRangeSec(unixts int64) bool {
	//fmt.Println(unixts, gTimeRangeStart/1000000000, gTimeRangeEnd/1000000000)
	return (0 == gTimeRangeStart || unixts >= (gTimeRangeStart/1000000000)) &&
		(0 == gTimeRangeEnd || unixts <= (gTimeRangeEnd/1000000000))
}

func InSpecifiedTimeRangeNs(unixts int64) bool {
	//fmt.Println(unixts, gTimeRangeStart, gTimeRangeEnd)
	return (0 == gTimeRangeStart || unixts >= (gTimeRangeStart)) &&
		(0 == gTimeRangeEnd || unixts <= (gTimeRangeEnd))
}

func HandleEvent(evt *EventWrapper) {
	switch evt.TableName {
	case "bpf_process_events":
		evtTs := GetTsFromUptime(evt.BpfProcessMsg.Columns.UptimeNanos)
		if IsGoArtStage(evt.BpfProcessMsg.Columns.Cmdline, evtTs) {
			return
		}
		if 0 != gExtractBeginTimestamp && 0 == gExtractEndTimestamp && InSpecifiedTimeRangeNs(evtTs) {
			IncludeEvent(evt.RawJsonStr, evt.BpfProcessMsg.ToSimple())
		}
	case "file_events":
		if InSpecifiedTimeRangeSec(evt.INotifyFileMsg.Columns.UnixTime) {
			IncludeEvent(evt.RawJsonStr, evt.INotifyFileMsg.ToSimple())
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

func ParseTimeRangeArg(s string, tstart *int64, tend *int64) {
	if 0 == len(s) {
		return
	}
	a := strings.SplitN(s,",",2)
	if len(a) != 2 {
		return
	}
	*tstart = ToInt64(a[0]) - 1000000000
	*tend = ToInt64(a[1]) + 1000000000
}

func GetSystemStartTimestamp() uint64 {
	loc, err := time.LoadLocation("Local")
	if err != nil {
		fmt.Println("ERROR: unable to load local TZ", err)
		return 0
	}
	cmd := exec.Command("uptime","-s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("ERROR: unable to run 'uptime -s'", err)
		return 0
	}
	uptimeStr := strings.TrimSpace(string(output))
	if gVerbose {
		fmt.Printf("system boot time (uptime -s):'%s'\n", uptimeStr)
	}
	t, _ := time.ParseInLocation("2006-01-02 15:04:05", uptimeStr, loc)
	return uint64(t.UnixNano())
}

func main() {
	if runtime.GOOS == "linux" {
		// bpf_process_events have ntime relative to uptime
		gSystemStartTime = GetSystemStartTimestamp()
	}
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

	ParseTimeRangeArg(flagTimeRangeStr, &gTimeRangeStart, &gTimeRangeEnd)

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

		outpath = flagResultsPath + "/simple_telemetry.json"
		gSimpleTelemetryOutputFile,err = os.OpenFile(outpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to create outfile",outpath, err)
			os.Exit(2)
		}
	}
	defer gTelemetryOutputFile.Close()
	defer gSimpleTelemetryOutputFile.Close()

	if flagDurationSeconds > 0 {
		time.Sleep(time.Duration(flagDurationSeconds) * time.Second)
	}


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
		gValidateState.StartTime = uint64(gExtractBeginTimestamp)
		gValidateState.EndTime = uint64(gExtractEndTimestamp)
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

		os.Exit(int(StatusDelegateValidation))
/*
		// set exit code if telemetry missing some expected items

		if gValidateState.Coverage == 1.0 {
			os.Exit(int(StatusValidateSuccess))
		} else if gValidateState.Coverage == 0.0 {
			os.Exit(int(StatusValidateFail))
		}
		os.Exit(int(StatusValidatePartial))
 */
	}
}
