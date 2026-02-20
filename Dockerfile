FROM golang:1.23-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /taskify-api ./src

FROM alpine:3.20
WORKDIR /app
RUN adduser -D -u 10001 appuser

COPY --from=builder /taskify-api /usr/local/bin/taskify-api
COPY src/config/config.yaml /app/src/config/config.yaml

USER appuser
EXPOSE 8080
CMD ["taskify-api"]
