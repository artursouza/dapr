module github.com/dapr/dapr/tests/apps/resiliencyapp_grpc

go 1.21

toolchain go1.22.0

require (
	github.com/dapr/dapr v1.7.4
	google.golang.org/grpc v1.59.0
	google.golang.org/grpc/examples v0.0.0-20220818173707-97cb7b1653d7
	google.golang.org/protobuf v1.32.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231012201019-e917dd12ba7a // indirect
)

replace github.com/dapr/dapr => ../../../
