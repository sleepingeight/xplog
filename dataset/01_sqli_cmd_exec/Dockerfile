FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod .
COPY main.go .
RUN go build -o emulator main.go

FROM alpine:3.19
RUN apk add --no-cache bash coreutils procps
WORKDIR /app
COPY --from=builder /build/emulator .


CMD ["sh", "-c", "./emulator --mode=${MODE} --duration=${DURATION}"]
