package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	types "github.com/secureworks/atomic-harness/pkg/types"
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

	gTotalMessages        = uint64(0)
	gTimeRangeStart = int64(0)
	gTimeRangeEnd = int64(0)
	gSystemStartTime = uint64(0)

	// {"name":"file_events","host
	gRxQueryName = regexp.MustCompile(`^."name":"([\w-_\d]+).*"numerics":([\w\d]+)`)
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

	// first get query 'name' and 'numerics' fields in string

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

	// we only care about events tables

	if !strings.HasSuffix(retval.TableName, "_events") {
		if gVerbose {
			fmt.Println("table name:",retval.TableName,"XXX")
		}
		return nil, nil
	}
	var err error

	// parse known event table schemas
	// Unfortunately, we require 'name' to match actual table_name.
	// Since numerics can be string or numbers, need to parse them
	// separately and convert to typed

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
	case "bpf_socket_events":
		if hasNumerics {
			msg := &BpfSocketEvent{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.BpfSocketMsg = msg

		} else {
			msg := &BpfSocketEventStr{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.BpfSocketMsg = msg.ToTyped()
		}
	default:
		if gVerbose {
			fmt.Println("Unsupported event table:", retval.TableName)
		}
		return nil, nil
	}

	return retval, nil
}

/**
 * IncludeEvent will write the event telemetry.json file.
 * If in delegation mode, will write to the simple_telemetry.json file.
 */
func IncludeEvent(rawJsonString string, simpleEvt *types.SimpleEvent) {
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

/**
 * GetTsFromUptime returns a nanosecond timestamp from uptime-nano
 * value.  This assumes that gSystemStartTime was set on startup.
 */
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
		if InSpecifiedTimeRangeNs(evtTs) {
			IncludeEvent(evt.RawJsonStr, evt.BpfProcessMsg.ToSimple())
		}
	case "bpf_socket_events":
		evtTs := GetTsFromUptime(evt.BpfSocketMsg.Columns.UptimeNanos)
		if InSpecifiedTimeRangeNs(evtTs) {
			IncludeEvent(evt.RawJsonStr, evt.BpfSocketMsg.ToSimple())
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

		evt,err := ParseEvent(line)
		if err != nil {
			fmt.Println(err)		
		}
		if evt == nil {
			continue
		}
		HandleEvent(evt)
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

/*
 * Get the timestamp for which uptimes are relative to
 */
func GetLinuxStartTimestamp() uint64 {
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
		gSystemStartTime = GetLinuxStartTimestamp()
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
		os.Exit(int(StatusDelegateValidation))
	}
}
