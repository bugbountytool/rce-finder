FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /fake-oob ./labs/oob/cmd/fake-oob
FROM gcr.io/distroless/static-debian12
COPY --from=build /fake-oob /fake-oob
USER 65532:65532
ENTRYPOINT ["/fake-oob"]
