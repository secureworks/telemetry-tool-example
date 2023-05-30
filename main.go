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
	"path/filepath"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

const (
	LinuxResultsPath = "/var/log/osquery/osqueryd.results.log"
	MacOSResultsPath = "/var/log/osquery/osqueryd.results.log"
	WinResultsPath = "C:\\Program Files\\osquery\\log\\osqueryd.results.log"
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
var flagResultsPath string
var flagFetch bool
var flagVerbose bool
var flagTimeRangeStr string
var flagClean bool
var flagPrepareMode bool
var flagOutputSuffix string

func init() {
	flag.BoolVar(&flagFetch, "fetch", false, "gather all event telemetry in time range. output to telemetry.json and simple_telemetry.json")
	flag.StringVar(&flagResultsPath, "resultsdir", "", "path to write results in validate mode")
	flag.BoolVar(&gVerbose, "verbose", false, "if true, logs more debug info")
	flag.StringVar(&flagTimeRangeStr, "ts", "", "start,end unix timestamps")
	flag.BoolVar(&flagClean, "clearcache", false, "flag not applicable")
	flag.BoolVar(&flagPrepareMode, "prepare", false, "called by harness before a run of tests")
	flag.StringVar(&flagOutputSuffix, "suffix", "", "optional suffix for files telemetry<suffix>.json and simple_telemetry<suffix>.json")
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
	case "es_process_events":
		if hasNumerics {
			msg := &EsProcessEvent{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.EsProcessEventMsg = msg

		} else {
			msg := &EsProcessEventStr{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.EsProcessEventMsg = msg.ToTyped()
		}
	case "es_process_file_events":
		if hasNumerics {
			msg := &EsFileEvent{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.EsFileEventMsg = msg
		} else {
			msg := &EsFileEventStr{}
			if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
				return nil, err
			}
			retval.EsFileEventMsg = msg.ToTyped()
		}
	case "windows_events":
		msg := &WinEvent{}
		if err = json.Unmarshal([]byte(rawJsonString), msg); err != nil {
			return nil, err
		}

		retval.WinEventMsg = msg

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
	case "es_process_file_events":
		if InSpecifiedTimeRangeSec(evt.EsFileEventMsg.Columns.UnixTime) {
			IncludeEvent(evt.RawJsonStr, evt.EsFileEventMsg.ToSimple())
		}
	case "es_process_events":
		evtTs := GetTsFromUptime(evt.EsProcessEventMsg.Columns.Time)
		if InSpecifiedTimeRangeNs(evtTs) {
			IncludeEvent(evt.RawJsonStr, evt.EsProcessEventMsg.ToSimple())
		}
	case "windows_events":

		t, _ := time.Parse(time.RFC3339, evt.WinEventMsg.Columns.DateTime)

		if InSpecifiedTimeRangeSec(t.Unix()) {
			if (evt.WinEventMsg.Columns.Eventid == "4688"){
				IncludeEvent(evt.RawJsonStr, evt.WinEventMsg.ToSimple())
			}
		}
	default:
	}

}

/*
 * for each line in osqueryd.results.log, parse and handle event
 */
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

/*
 * This parses the --ts argument string.
 * It has two unix timestamps separated by a comma.
 * The timestamps could be in seconds or nanoseconds.
 * example:
 *      --ts 1684198704,1684198754
 */
func ParseTimeRangeArg(s string, tstart *int64, tend *int64) {
	if 0 == len(s) {
		return
	}
	a := strings.SplitN(s,",",2)
	if len(a) != 2 {
		return
	}

	// if timestamp is in seconds, convert to nanos

	if len(a[0]) < 16 {
		a[0] = a[0] + "000000000"
		a[1] = a[1] + "000000000"
	}

	// parse

	*tstart = ToInt64(a[0])
	*tend = ToInt64(a[1])

	// widen range

	*tstart -= 1000000000
	*tend += 1000000000
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

	if true == flagPrepareMode {
		// flagClean only relevant in prepare mode
		fmt.Println("prepare - nothing to do")
		return
	}

	if false == flagFetch {
		fmt.Println("ERROR: only --fetch mode supported")
		os.Exit(int(types.StatusTelemetryToolFailure))
	}

	files := flag.Args()

	if flagTelemPath == "" {
		switch runtime.GOOS {
		case "darwin":
			flagTelemPath = MacOSResultsPath
		case "linux":
			flagTelemPath = LinuxResultsPath
		case "windows":
			flagTelemPath = WinResultsPath
		default:
			fmt.Println("no default telempath for ", runtime.GOOS)
			os.Exit(int(types.StatusTelemetryToolFailure))
		}
	}

	ParseTimeRangeArg(flagTimeRangeStr, &gTimeRangeStart, &gTimeRangeEnd)
	if 0 == gTimeRangeStart || 0 == gTimeRangeEnd {
		fmt.Println("ERROR: time range invalid or not specified", flagTimeRangeStr)
		os.Exit(int(types.StatusTelemetryToolFailure))
	}

	if flagFetch {
		var err error

		outpath := filepath.FromSlash(flagResultsPath + "/telemetry" + flagOutputSuffix + ".json")
		gTelemetryOutputFile,err = os.OpenFile(outpath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to create outfile",outpath, err)
			os.Exit(int(types.StatusTelemetryToolFailure))
		}

		outpath = filepath.FromSlash(flagResultsPath + "/simple_telemetry" + flagOutputSuffix + ".json")
		gSimpleTelemetryOutputFile,err = os.OpenFile(outpath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to create outfile",outpath, err)
			os.Exit(int(types.StatusTelemetryToolFailure))
		}
	}
	defer gTelemetryOutputFile.Close()
	defer gSimpleTelemetryOutputFile.Close()

	// we need to wait for events, assuming that the schedule is
	// outputting events on a minute schedule

	now := time.Now().Unix()
	deltaSec := now - (gTimeRangeEnd / 1000000000)
	if deltaSec < 65 {
		fmt.Println("Waiting for osquery schedule to gather events into results")
		time.Sleep(time.Duration(65) * time.Second)
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

	os.Exit(int(types.StatusDelegateValidation))
}
