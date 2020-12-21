# go-netvfy-agent
golang netvfy agent

## Development

After `git clone <repo_name`, running `go get -u` in the folder will cause go to grab all necessary dependencies and place them in the `~/$GOPATH/go/pkg/mod/` directory (simply `~$/go/pkg/mod/` if $GOPATH isn't definged.)

To add new dependencies simply run `go get <package_name/path>`. If you wish to vendor said dependencies (they'll be placed w/in the /vendor folder), run `go mod vendor` (which will copy over files from the pkg/mod directory). 
