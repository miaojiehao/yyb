FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/yyb-go ./cmd/yyb-go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/yyb-go /app/yyb-go
COPY resource /app/resource
VOLUME ["/app/resource/db"]
EXPOSE 8000

ENTRYPOINT ["/app/yyb-go"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--resource-root", "/app/resource"]
