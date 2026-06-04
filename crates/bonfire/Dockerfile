# Build Stage
ARG BASE_IMAGE=ghcr.io/kimani-club/base:latest
FROM ${BASE_IMAGE} AS builder

# Bundle Stage
FROM debian:bullseye-slim
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean
COPY --from=builder /home/rust/src/target/release/revolt-bonfire ./
EXPOSE 9000
CMD ["./revolt-bonfire"]
