FROM google/golang

RUN go get github.com/tools/godep

RUN mkdir -p /gopath/src/github.com/lavab/groove-webhook
ADD . /gopath/src/github.com/lavab/groove-webhook
RUN cd /gopath/src/github.com/lavab/groove-webhook && godep go install

CMD []
ENTRYPOINT ["/gopath/bin/groove-webhook"]
