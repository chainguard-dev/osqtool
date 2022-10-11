# osqtool

Tool to manage osquery packs and queries

## Usage

Create an osquery pack config from a directory of SQL files:

```shell
osqtool pack ./osx-attacks/
```

Create a directory of SQL files from a osquery pack config:

```shell
osqtool unpack osx-attacks.conf
```
