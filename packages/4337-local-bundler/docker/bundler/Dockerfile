FROM docker.io/library/node:18

# v0.7.0
ARG TAG=26e4f4c
RUN git clone https://github.com/eth-infinitism/bundler /src/bundler
WORKDIR /src/bundler
RUN git checkout ${TAG}
RUN git submodule init && git submodule update

# Patch EventsManager to handle the case where lastBlock > latestBlock in geth dev mode.
# Without this patch, sendNextBundle calls handlePastEvents which calls eth_getLogs(lastBlock, "latest").
# After a bundle is mined at block N, lastBlock is set to N+1. If no new block exists yet,
# eth_getLogs(N+1, "latest"=N) fails with "invalid block range params".
COPY docker/bundler/EventsManager.patch .
RUN patch -p1 < EventsManager.patch

RUN yarn && yarn preprocess
ENTRYPOINT ["yarn", "bundler"]
CMD []
