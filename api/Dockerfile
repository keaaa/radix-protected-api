FROM golang:alpine as builder
RUN apk update && apk add ca-certificates 

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /usr/local/bin/http-echo

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/bin/http-echo /usr/local/bin/http-echo
COPY --from=builder /app/swagger.json /swagger/swagger.json
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/http-echo"]
