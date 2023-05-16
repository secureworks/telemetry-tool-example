# telemtool example

Example of tool needed to fetch telemetry for the [atomic-harness](https://github.com/secureworks/atomic-harness) project.  This example demonstrates using [osquery](https://github.com/osquery/osquery) telemetry.

## osquery Linux Event Table Support

NOTE: The tool expects the schedule query to pull events to be named the same as the table.

- `bpf_process_events`
- `file_events` (inotify - no process info)
- `bpf_socket_events`

## osquery Linux config

```json
{
  // Configure the daemon below:
  "options": {

    "logger_path": "/var/log/osquery",
    "disable_events":false,
    "events_expiry":1,
    "events_max":50000,
    "enable_bpf_events":true,

    "enable_file_events":true,

    "schedule_splay_percent": "10",
    "use_gmt": true
  },

  // Define a schedule of queries:
  "schedule": {
    "bpf_process_events":{
       "query":"SELECT * FROM bpf_process_events",
       "interval":60
    },
    "bpf_socket_events":{
       "query":"SELECT * FROM bpf_socket_events WHERE family IN (2,23,17)",
       "interval":60
    },
    "file_events":{
       "query":"SELECT * FROM file_events",
       "interval":60
    }
  },

  "file_paths": {
    "custom_category": [
      "/etc/**",
      "/tmp/*"
    ],
    "device_nodes": [
      "/dev/*"
    ]
  },
  "file_accesses": [
    "custom_category"
  ],

  // Decorators are normal queries that append data to every query.
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
    ]
  }
}
```