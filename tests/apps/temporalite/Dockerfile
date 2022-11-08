FROM golang:1.18 as builder

WORKDIR ${GOPATH:-/go}/src/temporalite

RUN git clone https://github.com/temporalio/temporalite.git .
RUN git reset --hard 03d0be1d76babfbc1e3f2786ad74d5691d9f55d4

RUN go mod download
RUN go get -d -v ./...

RUN go build -o ${GOPATH:-/go}/bin/ ${GOPATH:-/go}/src/temporalite/cmd/temporalite

FROM gcr.io/distroless/base-debian11

COPY --from=builder ${GOPATH:-/go}/bin/temporalite /
EXPOSE 7233
EXPOSE 8233

ENTRYPOINT ["/temporalite", "start", "--ephemeral", "-n", "default", "--ip" , "0.0.0.0"]