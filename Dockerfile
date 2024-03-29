FROM golang:1.19-alpine AS builder
RUN apk update && apk add git make
WORKDIR /go/src/app
COPY . ./
ARG VERSION="main"
RUN make build VERSION=${VERSION}

FROM alpine:3.12
RUN apk --no-cache add ca-certificates
WORKDIR /
COPY --from=builder /go/src/app/job-pod-reaper .
USER 65534
ENTRYPOINT ["/job-pod-reaper"]
