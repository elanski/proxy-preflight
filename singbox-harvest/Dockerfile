# xray-knife как контейнер: альтернатива загрузке бинарника в CI
# и способ прогнать harvester локально без установки sing-box/xray на хост.
FROM python:3.11-slim-bookworm

ARG XK_VERSION=11.5.1
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Зафиксированная версия xray-knife (checksum.verify на CI-стороне)
RUN curl -fsSL "https://github.com/lilendian0x00/xray-knife/releases/download/v${XK_VERSION}/Xray-knife-linux-64.zip" -o /tmp/xk.zip \
    && unzip -oq /tmp/xk.zip -d /opt/xk && rm /tmp/xk.zip \
    && install -m 0755 /opt/xk/xray-knife /usr/local/bin/xray-knife \
    && xray-knife --version

WORKDIR /app
COPY singbox-harvest/requirements.txt /app/singbox-harvest/requirements.txt
RUN pip install --no-cache-dir -r /app/singbox-harvest/requirements.txt

COPY singbox-harvest /app/singbox-harvest
COPY cidrlist /app/cidrlist

WORKDIR /app
ENTRYPOINT ["python", "singbox-harvest/harvest.py"]
CMD ["--max-nodes", "400", "--backend", "fast", "--prescan", \
     "--out-dir", "singbox-harvest/out"]
