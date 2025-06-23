FROM node
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
RUN npx tsc
CMD ["node", "outDir/index.js"]
