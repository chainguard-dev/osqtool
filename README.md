# osqtool

Tool to manage osquery packs and queries

## Usage

### Unpack

Extract an osquery pack into a directory of SQL files:

```shell
osqtool --output=/tmp/out unpack osx-attacks.conf
```

Here is example output:

```log
Writing 745 bytes to /tmp/out/OceanLotus_dropped_file_1.sql ...
Writing 268 bytes to /tmp/out/OSX_MaMi_DNS_Servers.sql ...
Writing 328 bytes to /tmp/out/OSX_ColdRoot_RAT_Files.sql ...
Writing 209 bytes to /tmp/out/iWorm.sql ...
74 queries saved to /tmp/out
```

### Pack

Create an osquery pack configuration from a directory of SQL files:

```shell
osqtool pack /tmp/out
```

Here's the example output:

```json
{
  "queries": {
    "Aobo_Keylogger": {
      "query": "select * from launchd where name like 'com.ab.kl%.plist';",
      "interval": "3600",
      "version": "1.4.5",
      "description": "(http://aobo.cc/aobo-mac-os-x-keylogger.html)",
      "value": "Artifact used by this malware"
    },
    "Backdoor_MAC_Eleanor": {
      "query": "SELECT * FROM launchd WHERE name IN ('com.getdropbox.dropbox.integritycheck.plist','com.getdropbox.dropbox.timegrabber.plist','com.getdropbox.dropbox.usercontent.plist');",
      "interval": "3600",
      "version": "1.4.5",
      "description": "(https://blog.malwarebytes.com/cybercrime/2016/07/new-mac-backdoor-malware-eleanor/)",
      "value": "Artifact used by this malware"
    },
...
```

### Verify

Verify that the queries are valid in a pack, SQL file, or directory of SQL files

```shell
osqtool verify /tmp/out
```

Example output:

```log
Verifying "high-disk-bytes-written" ...
high-disk-bytes-written" returned 0 rows within 264.361831ms
Verifying "unexpected-shell-parents" ...
"unexpected-shell-parents" failed validation: /sbin/osqueryi --json [exit status 1]: Error: near line 1: near "sh": syntax error
78 queries found: 55 verified, 10 errored, 13 skipped
"verify" failed: 10 errors occurred:
 * xprotect-reports: /sbin/osqueryi --json [exit status 1]: Error: near line 1: no such table: xprotect_reports
...
```
