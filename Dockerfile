# Use Golang image as build stage environment.
FROM golang:1.24.5 AS build

# It should copy everything except the .dockerignore exclusions.
COPY . .

# Build a binary without libc bloat so it can be run on a static image.
RUN CGO_ENABLED=0 go build cmd/proxywall.go

# Use a static distroless image to minimize environment bloat.
FROM gcr.io/distroless/static-debian12

# Copy the build stage binary to the runtime.
COPY --from=build /go/proxywall .

# Specify the compiled binary as the image entry point.
ENTRYPOINT ["/proxywall"]

# vim: set ts=4 sw=4 noexpandtab:
