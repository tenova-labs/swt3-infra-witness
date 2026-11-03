FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /swt3-infra-witness ./cmd/swt3-infra-witness/

FROM gcr.io/distroless/static-debian12
COPY --from=build /swt3-infra-witness /swt3-infra-witness
USER 10001
EXPOSE 8080
ENTRYPOINT ["/swt3-infra-witness"]
CMD ["--mode", "server"]
