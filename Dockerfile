FROM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /iam-service ./src

FROM alpine:3.20
WORKDIR /app
RUN adduser -D -u 10001 appuser

COPY --from=builder /iam-service /usr/local/bin/iam-service

ENV HOST=0.0.0.0
ENV PORT=4003

USER appuser
EXPOSE 4003
CMD ["iam-service"]
