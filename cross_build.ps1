$env:GOOS="linux"
$env:GOARCH="arm64"
go build -o apl -ldflags="-s -w" ./