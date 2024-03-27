ARG RYU_VERSION=latest
FROM ghcr.io/scc365/ryu:${RYU_VERSION}

WORKDIR /controller
COPY router.py .
COPY arp.json .
COPY routing.json .

CMD [ "--ofp-tcp-listen-port", "6633", "./router.py" ]
