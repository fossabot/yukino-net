
FROM golang:1.17.1-alpine as builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o yukino-net .
RUN mkdir -p /etc/yukino-net

FROM gcr.io/distroless/base:nonroot

WORKDIR /bin
COPY --from=builder /app/yukino-net .
COPY --from=builder /etc/yukino-net /etc/yukino-net
VOLUME /etc/app/config
USER nonroot:nonroot

ENTRYPOINT ["/bin/yukino-net"]