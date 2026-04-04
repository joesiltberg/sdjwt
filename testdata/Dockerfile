FROM python:3.11-slim

# This Dockerfile builds an image that extracts SD-JWT test vectors from the
# OpenWallet Foundation (OWF) Labs SD-JWT reference implementation:
#   https://github.com/openwallet-foundation-labs/sd-jwt-python
#
# Usage:
#   docker build -t sdjwt-extract testdata/
#   docker run --rm -v "$PWD/testdata:/output" sdjwt-extract

# Install git (needed to clone the repository); clean up apt cache to reduce image size.
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Clone the OWF SD-JWT reference implementation and install it.
RUN git clone --depth 1 https://github.com/openwallet-foundation-labs/sd-jwt-python.git /sd-jwt-python && \
    pip install --no-cache-dir /sd-jwt-python

COPY extract_testcases.py /extract_testcases.py

CMD ["python", "/extract_testcases.py", "--repo-dir", "/sd-jwt-python", "--output", "/output/owf_reference_testcases.json"]
