# telemtool example

Example of tool needed to fetch telemetry for the [atomic-harness](https://github.com/secureworks/atomic-harness) project.  This example demonstrates using [osquery](https://github.com/osquery/osquery) telemetry.

## Overview
This tool will read in the /var/log/osquery/osqueryd.results.log, extract the supported events results.  It generates `telemetry.json` and `simple_telemetry.json` files, where the 'simple' is a conversion of each event into a schema that the atomic-harness understands.  The two files should have exactly the same number of lines, and line N in one file should match the event on same line in the other file.  The harness will extract the events for each atomic test run and do the matching against the criteria.

```sh
telemtool --fetch --resultsdir /tmp/somedir --ts 1684198704,1684198754
```

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

##Mac Config. Put it here `/var/osquery/osquery.conf`
```json
{
  "options": {

    "logger_path": "/var/log/osquery",
    "disable_events":false,
    "events_expiry":1,
    "events_max":50000,
    "disable_endpointsecurity": false,
    "disable_endpointsecurity_fim": false,
    "schedule_splay_percent": "10"
  },

  "schedule": {
    "es_process_events":{
       "query":"SELECT * FROM es_process_events",
       "interval":60
    },
    "es_process_file_events":{
       "query":"SELECT * FROM es_process_file_events",
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

  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;"
    ]
  }
}

```

##Windows Config 
```json
{
  "options": {

    "logger_path": "C:\\Program Files\\osquery\\log\\",
    "disable_events":false,
    "events_expiry":1,
    "events_max":50000,
    "enable_ntfs_event_publisher": true,
    "enable_powershell_events_subscriber": true,
    "enable_windows_events_publisher": true,
    "enable_windows_events_subscriber": true,
    "windows_event_channels":"System,Application,Setup,Security",
    "schedule_splay_percent": "10"
  },

  "schedule": {
    "process_etw_events":{
       "query":"SELECT * FROM process_etw_events",
       "interval":60
    }
  },

  "file_paths": {
    "custom_category": [
      "C:\\Users\\admin\\AppData\\Local\\Temp\\*"
    ],
    "device_nodes": [
    ]
  },
  "file_accesses": [
    "custom_category"
  ],

  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;"
    ]
  }
}

```