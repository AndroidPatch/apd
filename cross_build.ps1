$env:GOOS="linux"
$env:GOARCH="arm64"
go build -o apd -ldflags="-s -w" ./