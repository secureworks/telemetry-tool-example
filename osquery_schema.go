package main

/**
 * Structs for parsing osquery event table schema JSON
 * Since events can have string or numeric values, there
 * is special handling and conversion to get the typed instances.
 */

import (
	"fmt"
	"strconv"
)

//{"name":"bpf_process_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:00 2023 UTC","unixTime":1683584100,
//  "epoch":0,"counter":57,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},
// "columns":{"cid":"10198",
//   "cmdline":"bash /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash",
//   "cwd":"/home/amscwx","duration":"130942",
//   "exit_code":"0","gid":"0","ntime":"92306409329558",
//   "parent":"20468","path":"/usr/bin/bash","pid":"20478",
//   "probe_error":"0","syscall":"exec","tid":"20478","uid":"1002"},"action":"added"}

type BpfProcessEventColumns struct {
	Cmdline string       `json:"cmdline"`
	ExitCode int32       `json:"exit_code"`
	ParentPid int64      `json:"parent"`
	Path string
	Pid int64            `json:"pid"`
	SysCall string       `json:"syscall"`
	Tid int64            `json:"tid"`
	Uid int64            `json:"uid"`
	Gid int64            `json:"gid"`
	CGroupId int64       `json:"cid"`
	UptimeNanos uint64   `json:"ntime"`
	Cwd string           `json:"cwd"`
}

type BpfProcessEventColumnsStr struct {
	Cmdline string       `json:"cmdline"`
	ExitCode string       `json:"exit_code"`
	ParentPid string      `json:"parent"`
	Path string
	Pid string            `json:"pid"`
	SysCall string       `json:"syscall"`
	Tid string            `json:"tid"`
	Uid string            `json:"uid"`
	Gid string            `json:"gid"`
	CGroupId string       `json:"cid"`
	UptimeNanos string   `json:"ntime"`
	Cwd string           `json:"cwd"`
}

type BpfProcessEvent struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns BpfProcessEventColumns `json:"columns"`
}
type BpfProcessEventStr struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns BpfProcessEventColumnsStr `json:"columns"`
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

//{"name":"file_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:45 2023 UTC","unixTime":1683584145,"epoch":0,"counter":105,"numerics":false,
//   "decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},
//   "columns":{"action":"CREATED","atime":"","category":"custom_category","ctime":"","gid":"","hashed":"0","inode":"","md5":"","mode":"","mtime":"","sha1":"","sha256":"","size":"",
//       "target_path":"/tmp/passwd.zip","time":"1683584089","transaction_id":"0","uid":""},
// "action":"added"}

type INotifyEventColumns struct {
	TargetPath string    `json:"target_path"`
	Uid int64            `json:"uid"`
	Gid int64            `json:"gid"`
	Action string        `json:"action"`
	UnixTime int64       `json:"time"`
}

type INotifyFileEvent struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns INotifyEventColumns `json:"columns"`
}

type INotifyEventColumnsStr struct {
	TargetPath string    `json:"target_path"`
	Uid string           `json:"uid"`
	Gid string           `json:"gid"`
	Action string        `json:"action"`
	UnixTime string      `json:"time"`
}

type INotifyFileEventStr struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns INotifyEventColumnsStr `json:"columns"`
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

/*
{"name":"bpf_socket_events","hostIdentifier":"ubuntu","calendarTime":"Mon May 15 21:11:37 2023 UTC","unixTime":1684185097,"epoch":0,"counter":7816,"numerics":false,
  "decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"amscwx"},"columns":{
    "cid":"41430","duration":"56348","exit_code":"18446744073709551501","family":"2","fd":"106","gid":"1002","local_address":"","local_port":"0","ntime":"692196940063927",
    "parent":"108659","path":"/usr/lib/firefox/firefox","pid":"108660","probe_error":"0","protocol":"0","remote_address":"208.80.153.224","remote_port":"443",
    "syscall":"connect","tid":"108673","type":"1","uid":"1002"},"action":"added"}
*/

type BpfSocketEventColumnsStr struct {
	Pid string           `json:"pid"`
	Tid string           `json:"tid"`
	Uid string           `json:"uid"`
	Gid string           `json:"gid"`
	RemoteAddr string    `json:"remote_address"`
	RemotePort string    `json:"remote_port"`
	LocalAddr string     `json:"local_address"`
	LocalPort string     `json:"local_port"`
	UptimeNanos string   `json:"ntime"`
	Family string        `json:"family"` // AF_INET, etc
	ParentPid string     `json:"parent"`
	ExePath string       `json:"path"`
	Protocol string      `json:"protocol"`
	SysCall string       `json:"syscall"`
}

type BpfSocketEventColumns struct {
	Pid int64           `json:"pid"`
	Tid int64           `json:"tid"`
	Uid int64           `json:"uid"`
	Gid int64           `json:"gid"`
	RemoteAddr string   `json:"remote_address"`
	RemotePort int      `json:"remote_port"`
	LocalAddr string    `json:"local_address"`
	LocalPort int       `json:"local_port"`
	UptimeNanos uint64  `json:"ntime"`
	Family int          `json:"family"` // AF_INET, etc
	ParentPid int64     `json:"parent"`
	ExePath string      `json:"path"`
	Protocol int        `json:"protocol"`
	SysCall string      `json:"syscall"`
}

type BpfSocketEventStr struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns BpfSocketEventColumnsStr `json:"columns"`
}

type BpfSocketEvent struct {
	Name string                 `json:"name"`
	HostId string               `json:"hostIdentifier"`
	UnixTime int64             `json:"unixTime"`
	CalendarTime string         `json:"calendarTime"`
	Action string               `json:"action"`
	HasNumerics bool            `json:"numerics"`
	Columns BpfSocketEventColumns `json:"columns"`
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
	TableName        string
	RawJsonStr       string
	INotifyFileMsg   *INotifyFileEvent
	BpfProcessMsg    *BpfProcessEvent
	BpfSocketMsg     *BpfSocketEvent
}

// ================================== conversions to simple schema

/*
 * return a simplified event instance
 */
func (t *BpfProcessEvent) ToSimple() *SimpleEvent {
	ret := &SimpleEvent{}
	ret.EventType = SimpleSchemaProcess
	ret.Timestamp = GetTsFromUptime(t.Columns.UptimeNanos)

	fields := &SimpleProcessFields{}
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

func (t *BpfSocketEvent) ToSimple() *SimpleEvent {
	ret := &SimpleEvent{}
	ret.EventType = SimpleSchemaNetflow
	ret.Timestamp = GetTsFromUptime(t.Columns.UptimeNanos)

	fields := &SimpleNetflowFields{}

	fields.FlowStr = MakeFlowStr(t.Columns.Protocol, t.Columns.LocalAddr, t.Columns.LocalPort, t.Columns.RemoteAddr, t.Columns.RemotePort, t.Columns.SysCall)

	fields.ExePath = t.Columns.ExePath
	fields.Pid = t.Columns.Pid

	ret.NetflowFields = fields
	return ret
}

func (t *INotifyFileEvent) ToSimple() *SimpleEvent {
	ret := &SimpleEvent{}
	ret.EventType = SimpleSchemaFilemod            // Todo: read-only as well?
	ret.Timestamp = t.Columns.UnixTime*1000000000

	fields := &SimpleFileFields{}
	fields.TargetPath = t.Columns.TargetPath
	//fields.Uid = t.Columns.Uid

	switch t.Columns.Action {
	case "CREATED" :
		fields.Action = SimpleFileActionCreate
	case "UPDATED" :
		fields.Action = SimpleFileActionOpenWrite
	case "OPENED" :
		ret.EventType = SimpleSchemaFileRead
		fields.Action = SimpleFileActionOpenRead
	case "ACCESSED" :
		ret.EventType = SimpleSchemaFileRead
		fields.Action = SimpleFileActionOpenRead
	case "DELETED" :
		fields.Action = SimpleFileActionDelete
	case "ATTRIBUTES_MODIFIED":
		fields.Action = SimpleFileActionChmod
	default:
		fields.Action = SimpleFileActionUnknown
	}

	ret.FileFields = fields
	return ret
}
