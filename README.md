# helm ops_sanity_check

A helm3 plugin for performing sanity checks. Helm ops_sanity_check can be used to perform Pre and Post checks for deploying Opscruise product.

## Install Plugin

```sh
> helm plugin install [VCS_URL]
```

## Uninstall Plugin

```sh
> helm plugin uninstall ops_sanity_check
```

## Update Plugin
```sh
> helm plugin update ops_sanity_check
```

## Usage

* `helm ops_sanity_check pre-check`: Perform Pre-checks before deploying `Opscruise` components
* `helm ops_sanity_check post-check`: Perform Post-checks after deploying `Opscruise` components
* `helm ops_sanity_check --cleanup`: Cleanup the environment
* `helm ops_sanity_check --help`: print help


## Example

```sh
> helm ops_sanity_check pre-check
> helm ops_sanity_check post-check
```


## Requirements to run the plugin
* Ensure `kubectl` and `helm` commands are present
* K8s cluster should be accessible using `kubectl` command from where you run this plugin
* Ensure `opscruise-values.yaml` file is present under the location from where you run the plugin
