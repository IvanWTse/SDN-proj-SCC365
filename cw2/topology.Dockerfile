FROM ghcr.io/scc365/mininet:latest

RUN apt-get update && \
  apt-get install -yqq \
  curl \
  jq

RUN pip3 install flask

WORKDIR /topology
COPY topology.py .


CMD [ "topology.py" ]
