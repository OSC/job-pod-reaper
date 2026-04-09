FROM golang:1.26.2-alpine3.23 AS builder
RUN apk update && apk add git make
WORKDIR /go/src/app
COPY . .
ARG VERSION="main"
RUN make build VERSION=${VERSION}

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /go/src/app/job-pod-reaper .
USER 65534
ENTRYPOINT ["/job-pod-reaper"]
