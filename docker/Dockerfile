FROM python:3.11-slim

LABEL maintainer="LaxenT <[REDACTED]>"
LABEL description="LanScope - LAN reconnaissance (hardened)"

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iputils-ping \
    net-tools \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıkları
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

# Non-root kullanıcı oluştur
RUN useradd -m -s /bin/bash lanscope

# Binary'e yetki ver (setcap ile)
RUN setcap cap_net_raw,cap_net_admin+eip $(which python3) || true

# Kullanıcı değiştir
USER lanscope

ENTRYPOINT ["lanscope"]
CMD ["--help"]
