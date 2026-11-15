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

# Stage 3: free code scanners for source code reviews; checksum-verified
FROM python:3.12-slim AS scanners
ARG GITLEAKS_VERSION=8.30.0
ARG GITLEAKS_SHA256=79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e
ARG OSV_VERSION=2.3.0
ARG OSV_SHA256=e774e5770c31d60745c067be5f69bf3b46641b6d0e0ed87fd65e569cda35dc50
ADD https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz /tmp/gitleaks.tar.gz
ADD https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64 /tmp/osv-scanner
RUN echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
 && echo "${OSV_SHA256}  /tmp/osv-scanner" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
 && install -m 0755 /tmp/osv-scanner /usr/local/bin/osv-scanner \
 && chmod +x /usr/local/bin/gitleaks

# Stage 4: API server that also serves the built web app
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY --from=web /app/frontend/dist frontend/dist
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/osv-scanner /usr/local/bin/
# Bake the free community templates into the image; they are refreshed again when the server starts.
RUN nuclei -update-templates -duc -silent || echo "template download failed; will retry at start-up"
WORKDIR /app/backend
ENV PORT=8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
