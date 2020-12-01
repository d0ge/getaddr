FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y wget git gcc

RUN wget -P /tmp https://dl.google.com/go/go1.15.3.linux-amd64.tar.gz

RUN tar -C /usr/local -xzf /tmp/go1.15.3.linux-amd64.tar.gz
RUN rm /tmp/go1.15.3.linux-amd64.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -tags netcgo -o main .

# Move to /dist directory as the place for resulting binary folder
WORKDIR /dist

# Copy binary from build to main folder
RUN cp /build/main .

# Command to run when starting the container
CMD ["/dist/main"]