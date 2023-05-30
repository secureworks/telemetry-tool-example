package main

/**
 * Structs for parsing osquery event table schema JSON
 * Since events can have string or numeric values, there
 * is special handling and conversion to get the typed instances.
 */

import (
	"encoding/json"
	"fmt"
	"strconv"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

//{"name":"bpf_process_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:00 2023 UTC","unixTime":1683584100,
//  "epoch":0,"counter":57,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},
// "columns":{"cid":"10198",
//   "cmdline":"bash /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash",
//   "cwd":"/home/amscwx","duration":"130942",
//   "exit_code":"0","gid":"0","ntime":"92306409329558",
//   "parent":"20468","path":"/usr/bin/bash","pid":"20478",
//   "probe_error":"0","syscall":"exec","tid":"20478","uid":"1002"},"action":"added"}

/*
{"name":"es_process_events","hostIdentifier":"-","calendarTime":"Fri May 19 18:48:29 2023 UTC","unixTime":1684522109
,"epoch":0,"counter":124,"numerics":false,"decorations":{"host_uuid":"-"},
"columns":{"cdhash":"417240c5b4d100a9c727ee7d1e21b8298dc273d8","child_pid":"",
"cmdline":"/System/Library/CoreServices/Diagnostics Reporter.app/Contents/MacOS/Diagnostics Reporter ","cmdline_count":"1"
,"codesigning_flags":"","cwd":"/","egid":"20",
"env":"XPC_SERVICE_NAME=com.apple.DiagnosticsReporter SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.4wHTDv1WIP/Listeners
PATH=-"
,"env_count":"9","euid":"20","event_type":"exec","exit_code":"","gid":"20","global_seq_num":"4535","original_parent":"1",
"parent":"1","path":"/System/Library/CoreServices/Diagnostics Reporter.app/Contents/MacOS/Diagnostics Reporter","pid":"8369"
,"platform_binary":"1","seq_num":"2184","signing_id":"com.apple.DiagnosticsReporter","team_id":"","time":"1684522109"
,"uid":"501","username":"-","version":"5"},"action":"added"}
*/
/*
{"name":"windows_events","hostIdentifier":"DESKTOP-PVUQNBE","calendarTime":"Tue May 23 14:35:44 2023 UTC","unixTime":1684852544,"epoch":0,
"counter":37,"numerics":false,"decorations":{"host_uuid":"-"},
"columns":
{"computer_name":"DESKTOP-PVUQNBE",
"data":"{\"EventData\":{\"SubjectUserSid\":\"S-1-5-18\",\"SubjectUserName\":\"DESKTOP-PVUQNBE$\",
\"SubjectDomainName\":\"WORKGROUP\",\"SubjectLogonId\":\"0x3e7\",\"NewProcessId\":\"0x61d8\",
\"NewProcessName\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\"TokenElevationType\":\"%%1937\",\"ProcessId\":\"0x28d8\",
\"CommandLine\":\"\\\"C:\\\\WINDOWS\\\\system32\\\\notepad.exe\\\" \",\"TargetUserSid\":\"-\",
\"TargetUserName\":\"TopAcc\",\"TargetDomainName\":\"DESKTOP-PVUQNBE\",\"TargetLogonId\":\"0x5a40a6\",
\"ParentProcessName\":\"C:\\\\Windows\\\\explorer.exe\",\"MandatoryLabel\":\"S-1-16-12288\"}}",
"datetime":"2023-05-23T14:34:44.5348633Z","eventid":"4688","keywords":"0x8020000000000000","level":"0",
"provider_guid":"{-}","provider_name":"Microsoft-Windows-Security-Auditing","source":"Security",
"task":"13312","time":"1684852490"},
"action":"added"}
*/

type WinEventColumns struct {
	Eventid  string `json:"eventid"`
	Data     string `json:"data"`
	DateTime string `json:"datetime"`
}

type ProcessEventData struct {
	ProcessEventData WinProcessData `json:"EventData"`
}

type WinProcessData struct {
	NPid        string `json:"NewProcessId"`
	Pid         string `json:"ProcessId"`
	ProcessName string `json:"NewProcessName"`
	CommandLine string `json:"CommandLine"`
	User        string `json:"TargetUserName"`
	Parent      string `json:"ParentProcessName"`
}

type WinEvent struct {
	Name         string          `json:"name"`
	HostId       string          `json:"hostIdentifier"`
	UnixTime     int64           `json:"unixTime"`
	CalendarTime string          `json:"calendarTime"`
	Action       string          `json:"action"`
	HasNumerics  bool            `json:"numerics"`
	Columns      WinEventColumns `json:"columns"`
	Data         WinProcessData
	EventD       string
}

type BpfProcessEventColumns struct {
	Cmdline     string `json:"cmdline"`
	ExitCode    int32  `json:"exit_code"`
	ParentPid   int64  `json:"parent"`
	Path        string
	Pid         int64  `json:"pid"`
	SysCall     string `json:"syscall"`
	Tid         int64  `json:"tid"`
	Uid         int64  `json:"uid"`
	Gid         int64  `json:"gid"`
	CGroupId    int64  `json:"cid"`
	UptimeNanos uint64 `json:"ntime"`
	Cwd         string `json:"cwd"`
}

type EsProcessEventColumns struct {
	Cmdline   string `json:"cmdline"`
	ExitCode  int32  `json:"exit_code"`
	ParentPid int64  `json:"parent"`
	Path      string
	Env       string `json:"env"`
	Pid       int64  `json:"pid"`
	Uid       int64  `json:"uid"`
	Gid       int64  `json:"gid"`
	Cwd       string `json:"cwd"`
	Time      uint64 `json:"time"`
}

type BpfProcessEventColumnsStr struct {
	Cmdline     string `json:"cmdline"`
	ExitCode    string `json:"exit_code"`
	ParentPid   string `json:"parent"`
	Path        string
	Pid         string `json:"pid"`
	SysCall     string `json:"syscall"`
	Tid         string `json:"tid"`
	Uid         string `json:"uid"`
	Gid         string `json:"gid"`
	CGroupId    string `json:"cid"`
	UptimeNanos string `json:"ntime"`
	Cwd         string `json:"cwd"`
}

type EsProcessEventColumnsStr struct {
	Cmdline   string `json:"cmdline"`
	ExitCode  string `json:"exit_code"`
	ParentPid string `json:"parent"`
	Path      string
	Env       string `json:"env"`
	Pid       string `json:"pid"`
	Uid       string `json:"uid"`
	Gid       string `json:"gid"`
	Cwd       string `json:"cwd"`
	Time      string `json:"time"`
}

type BpfProcessEvent struct {
	Name         string                 `json:"name"`
	HostId       string                 `json:"hostIdentifier"`
	UnixTime     int64                  `json:"unixTime"`
	CalendarTime string                 `json:"calendarTime"`
	Action       string                 `json:"action"`
	HasNumerics  bool                   `json:"numerics"`
	Columns      BpfProcessEventColumns `json:"columns"`
}
type BpfProcessEventStr struct {
	Name         string                    `json:"name"`
	HostId       string                    `json:"hostIdentifier"`
	UnixTime     int64                     `json:"unixTime"`
	CalendarTime string                    `json:"calendarTime"`
	Action       string                    `json:"action"`
	HasNumerics  bool                      `json:"numerics"`
	Columns      BpfProcessEventColumnsStr `json:"columns"`
}

type EsProcessEvent struct {
	Name         string                `json:"name"`
	HostId       string                `json:"hostIdentifier"`
	UnixTime     int64                 `json:"unixTime"`
	CalendarTime string                `json:"calendarTime"`
	Action       string                `json:"action"`
	HasNumerics  bool                  `json:"numerics"`
	Columns      EsProcessEventColumns `json:"columns"`
}
type EsProcessEventStr struct {
	Name         string                   `json:"name"`
	HostId       string                   `json:"hostIdentifier"`
	UnixTime     int64                    `json:"unixTime"`
	CalendarTime string                   `json:"calendarTime"`
	Action       string                   `json:"action"`
	HasNumerics  bool                     `json:"numerics"`
	Columns      EsProcessEventColumnsStr `json:"columns"`
}

func ToInt64(valstr string) int64 {
	i, err := strconv.ParseInt(valstr, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func ToUInt64(valstr string) uint64 {
	i := ToInt64(valstr)
	return uint64(i)
}
func ToInt(valstr string) int {
	i := ToInt64(valstr)
	return int(i)
}

func ToInt32(valstr string) int32 {
	i := ToInt64(valstr)
	return int32(i)
}

func (t *BpfProcessEventStr) ToTyped() *BpfProcessEvent {
	ret := &BpfProcessEvent{t.Name, t.HostId, t.UnixTime, t.CalendarTime, t.Action, t.HasNumerics, BpfProcessEventColumns{}}
	ret.Columns.Cmdline = t.Columns.Cmdline
	ret.Columns.Path = t.Columns.Path
	ret.Columns.SysCall = t.Columns.SysCall
	ret.Columns.Cwd = t.Columns.Cwd
	ret.Columns.ExitCode = ToInt32(t.Columns.ExitCode)
	ret.Columns.ParentPid = ToInt64(t.Columns.ParentPid)
	ret.Columns.Pid = ToInt64(t.Columns.Pid)
	ret.Columns.Tid = ToInt64(t.Columns.Tid)
	ret.Columns.Uid = ToInt64(t.Columns.Uid)
	ret.Columns.Gid = ToInt64(t.Columns.Gid)
	ret.Columns.CGroupId = ToInt64(t.Columns.CGroupId)
	ret.Columns.UptimeNanos = ToUInt64(t.Columns.UptimeNanos)
	return ret
}

func (t *EsProcessEventStr) ToTyped() *EsProcessEvent {
	ret := &EsProcessEvent{t.Name, t.HostId, t.UnixTime, t.CalendarTime, t.Action, t.HasNumerics, EsProcessEventColumns{}}
	ret.Columns.Cmdline = t.Columns.Cmdline
	ret.Columns.Path = t.Columns.Path
	ret.Columns.Cwd = t.Columns.Cwd
	ret.Columns.Env = t.Columns.Env
	ret.Columns.ExitCode = ToInt32(t.Columns.ExitCode)
	ret.Columns.ParentPid = ToInt64(t.Columns.ParentPid)
	ret.Columns.Pid = ToInt64(t.Columns.Pid)
	ret.Columns.Uid = ToInt64(t.Columns.Uid)
	ret.Columns.Gid = ToInt64(t.Columns.Gid)
	ret.Columns.Gid = ToInt64(t.Columns.Gid)
	ret.Columns.Time = ToUInt64(t.Columns.Time)
	return ret
}

//{"name":"file_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:45 2023 UTC","unixTime":1683584145,"epoch":0,"counter":105,"numerics":false,
//   "decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},
//   "columns":{"action":"CREATED","atime":"","category":"custom_category","ctime":"","gid":"","hashed":"0","inode":"","md5":"","mode":"","mtime":"","sha1":"","sha256":"","size":"",
//       "target_path":"/tmp/passwd.zip","time":"1683584089","transaction_id":"0","uid":""},
// "action":"added"}

/*
{"name":"es_process_file_events","hostIdentifier":"-","calendarTime":"Fri May 19 18:46:41 2023 UTC",
"unixTime":1684522001,"epoch":0,"counter":116,"numerics":false,
"decorations":{"host_uuid":"A98A1A3B-B666-5233-8433-5D48A12FEF0E"},
"columns":{"dest_filename":"","event_type":"write",
"filename":"/private/var/root/Library/Logs/Bluetooth/bluetoothd-hci-latest.pklg",
"global_seq_num":"87594","parent":"1","path":"/usr/sbin/bluetoothd","pid":"148",
"seq_num":"77337","time":"1684521997","version":"5"},"action":"added"}
*/

type EsFileEventColumns struct {
	Path         string `json:"path"`
	EventType    string `json:"event_type"`
	Pid          int64  `json:"pid"`
	Parent       int64  `json:"parent"`
	Action       string `json:"action"`
	UnixTime     int64  `json:"time"`
	Filename     string `json:"filename"`
	DestFilename string `json:"dest_filename"`
}

type EsFileEvent struct {
	Name         string             `json:"name"`
	HostId       string             `json:"hostIdentifier"`
	UnixTime     int64              `json:"unixTime"`
	CalendarTime string             `json:"calendarTime"`
	Action       string             `json:"action"`
	HasNumerics  bool               `json:"numerics"`
	Columns      EsFileEventColumns `json:"columns"`
}

type EsFileEventColumnsStr struct {
	Path         string `json:"path"`
	EventType    string `json:"event_type"`
	Pid          string `json:"pid"`
	Parent       string `json:"parent"`
	Action       string `json:"action"`
	UnixTime     string `json:"time"`
	Filename     string `json:"filename"`
	DestFilename string `json:"dest_filename"`
}

type EsFileEventStr struct {
	Name         string                `json:"name"`
	HostId       string                `json:"hostIdentifier"`
	UnixTime     int64                 `json:"unixTime"`
	CalendarTime string                `json:"calendarTime"`
	Action       string                `json:"action"`
	HasNumerics  bool                  `json:"numerics"`
	Columns      EsFileEventColumnsStr `json:"columns"`
}

type INotifyEventColumns struct {
	TargetPath string `json:"target_path"`
	Uid        int64  `json:"uid"`
	Gid        int64  `json:"gid"`
	Action     string `json:"action"`
	UnixTime   int64  `json:"time"`
}

type INotifyFileEvent struct {
	Name         string              `json:"name"`
	HostId       string              `json:"hostIdentifier"`
	UnixTime     int64               `json:"unixTime"`
	CalendarTime string              `json:"calendarTime"`
	Action       string              `json:"action"`
	HasNumerics  bool                `json:"numerics"`
	Columns      INotifyEventColumns `json:"columns"`
}

type INotifyEventColumnsStr struct {
	TargetPath string `json:"target_path"`
	Uid        string `json:"uid"`
	Gid        string `json:"gid"`
	Action     string `json:"action"`
	UnixTime   string `json:"time"`
}

type INotifyFileEventStr struct {
	Name         string                 `json:"name"`
	HostId       string                 `json:"hostIdentifier"`
	UnixTime     int64                  `json:"unixTime"`
	CalendarTime string                 `json:"calendarTime"`
	Action       string                 `json:"action"`
	HasNumerics  bool                   `json:"numerics"`
	Columns      INotifyEventColumnsStr `json:"columns"`
}

func (t *INotifyFileEventStr) ToTyped() *INotifyFileEvent {
	ret := &INotifyFileEvent{t.Name, t.HostId, t.UnixTime, t.CalendarTime, t.Action, t.HasNumerics, INotifyEventColumns{}}
	ret.Columns.TargetPath = t.Columns.TargetPath
	ret.Columns.Action = t.Columns.Action
	ret.Columns.Uid = ToInt64(t.Columns.Uid)
	ret.Columns.Gid = ToInt64(t.Columns.Gid)
	ret.Columns.UnixTime = ToInt64(t.Columns.UnixTime)
	return ret
}

func (t *EsFileEventStr) ToTyped() *EsFileEvent {
	ret := &EsFileEvent{t.Name, t.HostId, t.UnixTime, t.CalendarTime, t.Action, t.HasNumerics, EsFileEventColumns{}}
	ret.Columns.Filename = t.Columns.Filename
	ret.Columns.DestFilename = t.Columns.DestFilename
	ret.Columns.Action = t.Columns.Action
	ret.Columns.Path = t.Columns.Path
	ret.Columns.EventType = t.Columns.EventType
	ret.Columns.Pid = ToInt64(t.Columns.Pid)
	ret.Columns.Parent = ToInt64(t.Columns.Parent)
	ret.Columns.UnixTime = ToInt64(t.Columns.UnixTime)
	return ret
}

/*
{"name":"bpf_socket_events","hostIdentifier":"ubuntu","calendarTime":"Mon May 15 21:11:37 2023 UTC","unixTime":1684185097,"epoch":0,"counter":7816,"numerics":false,
  "decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"amscwx"},"columns":{
    "cid":"41430","duration":"56348","exit_code":"18446744073709551501","family":"2","fd":"106","gid":"1002","local_address":"","local_port":"0","ntime":"692196940063927",
    "parent":"108659","path":"/usr/lib/firefox/firefox","pid":"108660","probe_error":"0","protocol":"0","remote_address":"208.80.153.224","remote_port":"443",
    "syscall":"connect","tid":"108673","type":"1","uid":"1002"},"action":"added"}
*/

type BpfSocketEventColumnsStr struct {
	Pid         string `json:"pid"`
	Tid         string `json:"tid"`
	Uid         string `json:"uid"`
	Gid         string `json:"gid"`
	RemoteAddr  string `json:"remote_address"`
	RemotePort  string `json:"remote_port"`
	LocalAddr   string `json:"local_address"`
	LocalPort   string `json:"local_port"`
	UptimeNanos string `json:"ntime"`
	Family      string `json:"family"` // AF_INET, etc
	ParentPid   string `json:"parent"`
	ExePath     string `json:"path"`
	Protocol    string `json:"protocol"`
	SysCall     string `json:"syscall"`
}

type BpfSocketEventColumns struct {
	Pid         int64  `json:"pid"`
	Tid         int64  `json:"tid"`
	Uid         int64  `json:"uid"`
	Gid         int64  `json:"gid"`
	RemoteAddr  string `json:"remote_address"`
	RemotePort  int    `json:"remote_port"`
	LocalAddr   string `json:"local_address"`
	LocalPort   int    `json:"local_port"`
	UptimeNanos uint64 `json:"ntime"`
	Family      int    `json:"family"` // AF_INET, etc
	ParentPid   int64  `json:"parent"`
	ExePath     string `json:"path"`
	Protocol    int    `json:"protocol"`
	SysCall     string `json:"syscall"`
}

type BpfSocketEventStr struct {
	Name         string                   `json:"name"`
	HostId       string                   `json:"hostIdentifier"`
	UnixTime     int64                    `json:"unixTime"`
	CalendarTime string                   `json:"calendarTime"`
	Action       string                   `json:"action"`
	HasNumerics  bool                     `json:"numerics"`
	Columns      BpfSocketEventColumnsStr `json:"columns"`
}

type BpfSocketEvent struct {
	Name         string                `json:"name"`
	HostId       string                `json:"hostIdentifier"`
	UnixTime     int64                 `json:"unixTime"`
	CalendarTime string                `json:"calendarTime"`
	Action       string                `json:"action"`
	HasNumerics  bool                  `json:"numerics"`
	Columns      BpfSocketEventColumns `json:"columns"`
}

func (t *BpfSocketEventStr) ToTyped() *BpfSocketEvent {
	ret := &BpfSocketEvent{t.Name, t.HostId, t.UnixTime, t.CalendarTime, t.Action, t.HasNumerics, BpfSocketEventColumns{}}
	ret.Columns.ExePath = t.Columns.ExePath
	ret.Columns.LocalAddr = t.Columns.LocalAddr
	ret.Columns.RemoteAddr = t.Columns.RemoteAddr
	ret.Columns.SysCall = t.Columns.SysCall

	ret.Columns.Protocol = ToInt(t.Columns.Protocol)
	ret.Columns.LocalPort = ToInt(t.Columns.LocalPort)
	ret.Columns.RemotePort = ToInt(t.Columns.RemotePort)
	ret.Columns.Uid = ToInt64(t.Columns.Uid)
	ret.Columns.Gid = ToInt64(t.Columns.Gid)
	ret.Columns.Pid = ToInt64(t.Columns.Pid)
	ret.Columns.ParentPid = ToInt64(t.Columns.ParentPid)
	ret.Columns.Tid = ToInt64(t.Columns.Tid)

	ret.Columns.UptimeNanos = ToUInt64(t.Columns.UptimeNanos)
	return ret
}

type EventWrapper struct {
	TableName         string
	RawJsonStr        string
	INotifyFileMsg    *INotifyFileEvent
	BpfProcessMsg     *BpfProcessEvent
	BpfSocketMsg      *BpfSocketEvent
	EsProcessEventMsg *EsProcessEvent
	EsFileEventMsg    *EsFileEvent
	WinEventMsg       *WinEvent
}

// ================================== conversions to simple schema
func (t *WinEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaProcess
	ret.Timestamp = t.UnixTime

	fields := &types.SimpleProcessFields{}
	data := &ProcessEventData{}
	json.Unmarshal([]byte(t.Columns.Data), &data)
	fields.Cmdline = data.ProcessEventData.CommandLine
	fields.ExePath = data.ProcessEventData.ProcessName
	if len(data.ProcessEventData.NPid) > 2 {
		fields.Pid, _ = strconv.ParseInt(string(data.ProcessEventData.NPid[2:len(data.ProcessEventData.NPid)]), 16, 64)
	}
	if len(data.ProcessEventData.Pid) > 2 {
		fields.ParentPid, _ = strconv.ParseInt(string(data.ProcessEventData.Pid[2:len(data.ProcessEventData.Pid)]), 16, 64)
	}
	ret.ProcessFields = fields
	return ret
}

func (t *EsProcessEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaProcess
	ret.Timestamp = GetTsFromUptime(t.Columns.Time)

	fields := &types.SimpleProcessFields{}
	fields.Cmdline = t.Columns.Cmdline
	fields.ExePath = t.Columns.Path
	fields.Pid = t.Columns.Pid
	fields.ParentPid = t.Columns.ParentPid

	ret.ProcessFields = fields
	return ret
}

func (t *EsFileEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaFilemod // Todo: read-only as well?
	ret.Timestamp = t.Columns.UnixTime * 1000000000

	fields := &types.SimpleFileFields{}
	fields.TargetPath = t.Columns.Filename
	//fields.Uid = t.Columns.Uid

	switch t.Columns.EventType {
	case "create":
		fields.Action = types.SimpleFileActionCreate
	case "write":
		fields.Action = types.SimpleFileActionOpenWrite
	case "open":
		ret.EventType = types.SimpleSchemaFileRead
		fields.Action = types.SimpleFileActionOpenRead
	case "unlink":
		fields.Action = types.SimpleFileActionDelete
	case "setmode":
		fields.Action = types.SimpleFileActionChmod
	default:
		fields.Action = types.SimpleFileActionUnknown
	}

	ret.FileFields = fields
	return ret
}

/*
 * return a simplified event instance
 */
func (t *BpfProcessEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaProcess
	ret.Timestamp = GetTsFromUptime(t.Columns.UptimeNanos)

	fields := &types.SimpleProcessFields{}
	fields.Cmdline = t.Columns.Cmdline
	fields.ExePath = t.Columns.Path
	fields.Pid = t.Columns.Pid
	fields.ParentPid = t.Columns.ParentPid

	ret.ProcessFields = fields
	return ret
}

const IpProtoTcp int = 6
const IpProtoIcmp int = 1
const IpProtoUdp int = 17

func MakeFlowStr(protocol int, laddr string, lport int, raddr string, rport int, sysCall string) string {
	proto := "?"
	switch protocol {
	case 0:
		switch sysCall {
		case "connect":
			protocol = IpProtoTcp
			proto = "tcp"
		}
	case IpProtoTcp:
		proto = "tcp"
	case IpProtoUdp:
		proto = "udp"
	case IpProtoIcmp:
		proto = "icmp"
	}
	if len(laddr) == 0 {
		laddr = "0.0.0.0"
	}

	s := proto + ":" + laddr + ":" + fmt.Sprintf("%d", lport)
	s += "->" + raddr + ":" + fmt.Sprintf("%d", rport)

	return s
}

func (t *BpfSocketEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaNetflow
	ret.Timestamp = GetTsFromUptime(t.Columns.UptimeNanos)

	fields := &types.SimpleNetflowFields{}

	fields.FlowStr = MakeFlowStr(t.Columns.Protocol, t.Columns.LocalAddr, t.Columns.LocalPort, t.Columns.RemoteAddr, t.Columns.RemotePort, t.Columns.SysCall)

	//fields.ExePath = t.Columns.ExePath
	//fields.Pid = t.Columns.Pid

	ret.NetflowFields = fields
	return ret
}

func (t *INotifyFileEvent) ToSimple() *types.SimpleEvent {
	ret := &types.SimpleEvent{}
	ret.EventType = types.SimpleSchemaFilemod // Todo: read-only as well?
	ret.Timestamp = t.Columns.UnixTime * 1000000000

	fields := &types.SimpleFileFields{}
	fields.TargetPath = t.Columns.TargetPath
	//fields.Uid = t.Columns.Uid

	switch t.Columns.Action {
	case "CREATED":
		fields.Action = types.SimpleFileActionCreate
	case "UPDATED":
		fields.Action = types.SimpleFileActionOpenWrite
	case "OPENED":
		ret.EventType = types.SimpleSchemaFileRead
		fields.Action = types.SimpleFileActionOpenRead
	case "ACCESSED":
		ret.EventType = types.SimpleSchemaFileRead
		fields.Action = types.SimpleFileActionOpenRead
	case "DELETED":
		fields.Action = types.SimpleFileActionDelete
	case "ATTRIBUTES_MODIFIED":
		fields.Action = types.SimpleFileActionChmod
	default:
		fields.Action = types.SimpleFileActionUnknown
	}

	ret.FileFields = fields
	return ret
}
