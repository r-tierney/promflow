FROM debian:stretch

# Install Go
RUN apt-get update && apt-get install -y wget gcc libpcap-dev \
    && wget https://dl.google.com/go/go1.19.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.19.4.linux-amd64.tar.gz \
    && rm go1.19.4.linux-amd64.tar.gz

# Set Go environment variables
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

# Copy the source code and change to the correct directory
COPY . /go/src/myproject
WORKDIR /go/src/myproject

# Build the binary
RUN go build -o myproject

# Run the binary by default when the container starts
ENTRYPOINT ["./myproject"]
