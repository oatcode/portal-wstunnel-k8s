## Build
FROM golang:1.17-alpine AS builder
WORKDIR /build
COPY . ./
RUN go build -o wstunnel.bin

## Deploy
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /build/wstunnel.bin ./
EXPOSE 8080
ENTRYPOINT ["./wstunnel.bin"]
