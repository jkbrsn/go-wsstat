**ARCHIVED**: from the merge of https://github.com/jkbrsn/wsstat/pull/18 this library will live on in the [wsstat](https://github.com/jkbrsn/wsstat) repo, together with the CLI client.

# go-wsstat [![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs] [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)][license]

[godocs]: http://godoc.org/github.com/jkbrsn/go-wsstat
[license]: /LICENSE

Use the `go-wsstat` Golang package to trace WebSocket connection and latency in your Go applications. It wraps the [gorilla/websocket](https://pkg.go.dev/github.com/gorilla/websocket) package for the WebSocket protocol implementation, and measures the duration of the different phases of the connection cycle. The program takes inspiration from the [go-httpstat](https://github.com/tcnksm/go-httpstat) package, which is useful for tracing HTTP requests.

## Install

Install to use in your project with `go get`:

```bash
go get github.com/jkbrsn/go-wsstat
```

## Usage

The [_example/main.go](./_example/main.go) program demonstrates two ways to use the `go-wsstat` package to trace a WebSocket connection. The example only executes one-hit message reads and writes, but WSStat also support operating on a continuous connection.

Run the example:

```bash
go run _example/main.go <a WebSocket URL>
```

### Testing the package

Run the tests:

```bash
make test
```
