FROM golang:1.23.4 AS builder

WORKDIR /app

COPY . .
COPY .env .

RUN CGO_ENABLED=0 GOOS=linux go build -o app ./cmd/server/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/app .
COPY --from=builder /app/.env .env

EXPOSE 8080

CMD ["./app"]
