# go-netvfy-agent
golang netvfy agent

## Dependencies and Vendoring 

After `git clone <repo_name>`, running `go get -u` in the folder will cause go to grab all necessary dependencies and place them in the `~/$GOPATH/go/pkg/mod/` directory (simply `~$/go/pkg/mod/` if $GOPATH isn't definged.)

To add new dependencies simply run `go get <package_name/path>`. 

If you wish to vendor said dependencies (they'll be placed w/in the /vendor folder), run `go mod vendor` (which will copy over files from the pkg/mod directory). 

## Running and Testing Locally

To test and ensure staticchecks, lints, etc pass run the following make commands: 

```
$ make test
$ make staticcheck
$ make vet
$ make fmt
```

To build the netvfy CLI agent, run: 

```
$ make netvfy-agent
```

## Deployment 

TBD. 