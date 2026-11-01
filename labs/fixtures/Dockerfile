FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /fixture ./labs/fixtures/cmd/fixture
FROM gcr.io/distroless/static-debian12
COPY --from=build /fixture /fixture
USER 65532:65532
ENTRYPOINT ["/fixture"]
