# getaddr

Tiny Go tool to bruteforce Unix DNS resolver. Pay attention that behavior netdns=go/cgo may diff. Force low level resolver with build tag netcgo

## Build

`go build -tags netcgo getaddr.go`

## Docker

```bash
docker build . -t go-final
docker images
docker run -i -t <image_id> /bin/bash
docker cp <container_id>:/dist/results.txt ./
```

## Results

### Ubuntu latest

```bash
"127.0.0.1\x00127.0.0.2"	[127.0.0.1]
"::127.0.0.1%127.0.0.2"	[::7f00:1]
```

### Ubuntu 16.04

```bash
"127.0.0.1\x00127.0.0.2"	[127.0.0.1]
"127.0.0.1\t127.0.0.2"	[127.0.0.1]
"127.0.0.1\n127.0.0.2"	[127.0.0.1]
"127.0.0.1\v127.0.0.2"	[127.0.0.1]
"127.0.0.1\f127.0.0.2"	[127.0.0.1]
"127.0.0.1\r127.0.0.2"	[127.0.0.1]
"127.0.0.1 127.0.0.2"	[127.0.0.1]
"::127.0.0.1\x00127.0.0.2"	[::7f00:1]
"::127.0.0.1%127.0.0.2"	[::7f00:1]
```
