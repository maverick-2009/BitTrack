FROM node:20-alpine
WORKDIR /app
COPY BitTrack.js .
COPY monitor.js .
COPY descriptor-parser.js .
COPY panel.js .
COPY panel.html .
RUN mkdir -p /app/data
COPY data/example.config.json /app/data/config.json
COPY data/example.servers.json /app/data/servers.json
COPY data/example.state.json /app/data/state.json
COPY data/example.wallets.json /app/data/wallets.json
EXPOSE 8585
CMD ["node", "BitTrack.js"]