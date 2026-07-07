FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir -e ".[web]"

# Optional OSINT binaries available via pip
RUN pip install --no-cache-dir holehe sherlock-project sublist3r

RUN mkdir -p /app/reports

EXPOSE 8080

CMD ["clearfront", "web", "--host", "0.0.0.0", "--port", "8080", "--no-browser"]
