# logbook — pure-Go (modernc SQLite), so CGO stays off and the runtime image
# is a bare alpine with certificates for the notify-relay escalation calls.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /logbook .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && mkdir -p /data
COPY --from=build /logbook /usr/local/bin/logbook
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8080/livez || exit 1
CMD ["logbook"]
