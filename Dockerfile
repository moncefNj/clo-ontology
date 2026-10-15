# CLO -- ontology, rules, tools and CLO Studio in one container.
#   docker build -t clo .
#   docker run --rm -p 8000:8000 clo          # tests, rebuild CLO Studio, serve it on http://localhost:8000
#   docker run --rm -it clo bash               # shell with everything installed (make reproduce-fast, ...)
FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends default-jre-headless make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /clo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "make test && make demo && echo 'CLO Studio: http://localhost:8000/clo_studio.html' && python -m http.server 8000 --directory examples/demo"]
