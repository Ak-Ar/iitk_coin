FROM golang:latest 

RUN mkdir /build
WORKDIR /build

RUN export GO111MODULE=on
RUN go get github.com/Ak-Ar/iitk_coin
RUN cd /build && git clone https://github.com/Ak-Ar/iitk_coin.git

RUN cd /build/iitk_coin && go build
EXPOSE 8080

ENTRYPOINT ["/build/iitk_coin/iitk_coin"]