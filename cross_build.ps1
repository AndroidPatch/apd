$env:GOOS="linux"
$env:GOARCH="arm64"
$env:CGO_ENABLED=1
go build -o apd -ldflags="-s -w" ./