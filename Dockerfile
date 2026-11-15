# Stage 1: build the web app
FROM node:22-slim AS web
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Stage 2: Nuclei (free, MIT-licensed) for consent-based in-depth scans; checksum-verified
FROM python:3.12-slim AS nuclei
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ADD https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip /tmp/nuclei.zip
RUN echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
 && python -c "import zipfile; zipfile.ZipFile('/tmp/nuclei.zip').extract('nuclei', '/usr/local/bin')" \
 && chmod +x /usr/local/bin/nuclei

# Stage 3: API server that also serves the built web app
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY --from=web /app/frontend/dist frontend/dist
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
# Bake the free community templates into the image; they are refreshed again when the server starts.
RUN nuclei -update-templates -duc -silent || echo "template download failed; will retry at start-up"
WORKDIR /app/backend
ENV PORT=8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
