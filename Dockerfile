FROM node:22-slim

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy holochain binary + its nix store dependencies
# The binary is linked against nix glibc — we need the full closure
COPY holochain-nix-closure.tar.gz /tmp/
RUN tar xzf /tmp/holochain-nix-closure.tar.gz -C / && \
    rm /tmp/holochain-nix-closure.tar.gz

COPY holochain-bin /usr/local/bin/holochain
RUN chmod +x /usr/local/bin/holochain


# Copy app files
COPY package*.json ./
COPY api/ ./api/
COPY scripts/ ./scripts/
COPY workdir/ ./workdir/
COPY dnas/ ./dnas/
COPY conductor-config.yaml ./

COPY patches/ ./patches/
RUN npm install --ignore-scripts

COPY relay-cert.pem /usr/local/share/ca-certificates/relay-cert.crt
RUN update-ca-certificates
RUN mkdir -p /data

ENV DATA_DIR=/data
ENV ADMIN_PORT=44121
ENV APP_PORT=44122
ENV API_PORT=3000

EXPOSE 3000

COPY start-production.sh ./
RUN chmod +x start-production.sh

CMD ["./start-production.sh"]