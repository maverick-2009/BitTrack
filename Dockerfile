FROM node:20-alpine
WORKDIR /app
COPY BitTrack.js .
COPY monitor.js .
COPY descriptor-parser.js .
COPY panel.js .
COPY panel.html .
COPY language/ ./language/
EXPOSE 8585
CMD ["node", "BitTrack.js"]