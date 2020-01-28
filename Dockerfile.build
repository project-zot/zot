FROM golang:1.12.8

RUN go version
ENV GO111MODULE on
RUN go get -u github.com/swaggo/swag/cmd/swag
WORKDIR /go/src/github.com/anuvu/zot
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.17.1
