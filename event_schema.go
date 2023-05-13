package main

import (
	"strconv"
)

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


//{"name":"proc_events","hostIdentifier":"ubuntu","calendarTime":"Mon May  8 22:15:00 2023 UTC","unixTime":1683584100,
//  "epoch":0,"counter":57,"numerics":false,"decorations":{"host_uuid":"48754d56-277e-7cb6-dd7b-f58673f0c7fd","username":"develop"},
// "columns":{"cid":"10198",
//   "cmdline":"bash /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash",
//   "cwd":"/home/amscwx","duration":"130942",
//   "exit_code":"0","gid":"0","ntime":"92306409329558",
//   "parent":"20468","path":"/usr/bin/bash","pid":"20478",
//   "probe_error":"0","syscall":"exec","tid":"20478","uid":"1002"},"action":"added"}

/*
  process_file_events (audit)
----------
operation	TEXT Operation type
pid	BIGINT Process ID
ppid	BIGINT Parent process ID
time	BIGINT Time of execution in UNIX time
executable	TEXT The executable path 
partial	TEXT True if this is a partial event (i.e.: this process existed before we started osquery)
cwd	TEXT The current working directory of the process
path	TEXT The path associated with the event
dest_path	TEXT The canonical path associated with the event
uid	TEXT The uid of the process performing the action
gid	TEXT The gid of the process performing the action
auid	TEXT Audit user ID of the process using the file
euid	TEXT Effective user ID of the process using the file
egid	TEXT Effective group ID of the process using the file
fsuid	TEXT Filesystem user ID of the process using the file
fsgid	TEXT Filesystem group ID of the process using the file
suid	TEXT Saved user ID of the process using the file
sgid	TEXT Saved group ID of the process using the file
uptime	BIGINT Time of execution in system uptime
eid	TEXT Event ID
 */

/*
file_events (inotify - no process info)
----------
target_path	TEXT The path associated with the event
category	TEXT The category of the file defined in the config
action	TEXT Change action (UPDATE, REMOVE, etc)
transaction_id	BIGINT ID used during bulk update
inode	BIGINT Filesystem inode number
uid	BIGINT Owning user ID
gid	BIGINT Owning group ID
mode	TEXT Permission bits
size	BIGINT Size of file in bytes
atime	BIGINT Last access time
mtime	BIGINT Last modification time
ctime	BIGINTLast status change time
md5	TEXT The MD5 of the file after change
sha1	TEXT The SHA1 of the file after change
sha256	TEXT The SHA256 of the file after change
hashed	INTEGER 1 if the file was hashed, 0 if not, -1 if hashing failed
time	BIGINT Time of file event
eid	TEXT Event ID
*/
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
	return ret
}

type EventWrapper struct {
	TableName string
	RawJsonStr       string
	INotifyFileMsg   *INotifyFileEvent
	BpfProcessMsg    *BpfProcessEvent
}
