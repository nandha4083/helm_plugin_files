# [South] Pre and Post deployment checks

This bash script can be used to perform Pre and Post deployment checks in South.

## Download script

```sh
> wget https://opscruise-helm.bitbucket.io/ops_plugin.sh -O ops_plugin.sh
```

## Usage

```sh
> bash ops_plugin.sh --help
Usage: helm ops_sanity_check <COMMAND> <SUB_COMMAND>
Available Commands:
    pre-check                 Perform Pre-checks
    post-check                Perform Post-checks
    --help                    Display this text
    --cleanup                 To explicitly run the cleanup. Default action
Available Sub-Commands:
    --disable-cleanup         To disable cleanup
```

## Examples

* `bash ops_plugin.sh pre-check`: Perform Pre-checks before deploying `Opscruise` components
* `bash ops_plugin.sh post-check`: Perform Post-checks after deploying `Opscruise` components
* `bash ops_plugin.sh --cleanup`: Cleanup the environment


## Requirements to run the plugin
* Ensure `kubectl` and `helm` commands are present
* K8s cluster should be accessible using `kubectl` command from where you run this plugin
* Ensure `opscruise-values.yaml` file is present under the location from where you run the plugin
