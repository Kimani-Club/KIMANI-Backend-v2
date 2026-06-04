# Build Stage
ARG BASE_IMAGE=ghcr.io/kimani-club/base:latest
FROM ${BASE_IMAGE} AS builder

# Bundle Stage
FROM debian:bullseye-slim
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean
COPY --from=builder /home/rust/src/target/release/revolt-delta ./

EXPOSE 8000
ENV ROCKET_ADDRESS 0.0.0.0
ENV ROCKET_PORT 8000
CMD ["./revolt-delta"]
