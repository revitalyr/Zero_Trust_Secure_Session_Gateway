# Multi-stage Dockerfile for Zero Trust Secure Session Gateway
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV CMAKE_BUILD_TYPE=Release

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libboost-all-dev \
    libssl-dev \
    libspdlog-dev \
    nlohmann-json3-dev \
    libyaml-cpp-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# Create source directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN mkdir -p build && \
    cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
        -DBUILD_TESTING=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build . --parallel && \
    make install

# Production stage
FROM ubuntu:22.04 AS production

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV ZEROSSG_LOG_LEVEL=info
ENV ZEROSSG_LISTEN_PORT=8443

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libboost-system1.74.0 \
    libboost-thread1.74.0 \
    libboost-chrono1.74.0 \
    libboost-date-time1.74.0 \
    libboost-filesystem1.74.0 \
    libssl1.1 \
    libspdlog1 \
    nlohmann-json3 \
    libyaml-cpp0.7 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r zerossg && \
    useradd -r -g zerossg -d /app -s /sbin/nologin zerossg

# Create application directories
RUN mkdir -p /app/{logs,config,certs} && \
    chown -R zerossg:zerossg /app

# Copy built application from builder stage
COPY --from=builder /usr/local/bin/zerossg_gateway /usr/local/bin/
COPY --from=builder /usr/local/lib /usr/local/lib/

# Copy configuration files
COPY --chown=zerossg:zerossg examples/config.json /app/config/
COPY --chown=zerossg:zerossg examples/config.yaml /app/config/

# Create default log directory
RUN mkdir -p /var/log/zerossg && \
    chown zerossg:zerossg /var/log/zerossg

# Switch to non-root user
USER zerossg
WORKDIR /app

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD zerossg_gateway status || exit 1

# Set entrypoint
ENTRYPOINT ["zerossg_gateway"]
CMD ["start", "/app/config/config.json"]

# Labels
LABEL maintainer="Zero Trust Security Team" \
      version="1.0.0" \
      description="Zero Trust Secure Session Gateway" \
      org.opencontainers.image.title="Zero Trust Secure Session Gateway" \
      org.opencontainers.image.description="Production-grade Zero Trust gateway for secure remote access" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="Zero Trust Security" \
      org.opencontainers.image.licenses="MIT"
