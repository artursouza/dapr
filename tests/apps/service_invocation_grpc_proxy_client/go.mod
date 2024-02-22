module github.com/dapr/dapr/tests/apps/service_invocation_grpc_proxy_client

go 1.21

toolchain go1.22.0

require (
	github.com/dapr/dapr v0.0.0-00010101000000-000000000000
	github.com/gorilla/mux v1.8.1
	google.golang.org/grpc v1.59.0
	google.golang.org/grpc/examples v0.0.0-20210610163306-6351a55c3895
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231012201019-e917dd12ba7a // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)

replace github.com/dapr/dapr => ../../../
