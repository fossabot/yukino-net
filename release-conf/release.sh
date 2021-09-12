#!/bin/sh

SRC_FOLDER=..
OUTPUT_FOLDER=releases
VERSION_NUMBER=$1

[ ! -d $OUTPUT_FOLDER ] && mkdir $OUTPUT_FOLDER

for ARCH in arm64 amd64; do
echo "Building package for ${ARCH}"
GOOS=linux GOARCH=$ARCH go build -ldflags "-s -w" -o build/$ARCH/yukino-net $SRC_FOLDER
go-bin-deb generate -a $ARCH --version "${VERSION_NUMBER?}" -w pkg-build/$ARCH/ -o $OUTPUT_FOLDER/yukino-net-$ARCH.deb
done

GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $OUTPUT_FOLDER/yukino-net.exe $SRC_FOLDER

GOOS=linux GOARCH=arm go build -ldflags "-s -w" -o build/armhf/yukino-net $SRC_FOLDER
go-bin-deb generate -a armhf --version "${VERSION_NUMBER?}" -w pkg-build/armhf/ -o $OUTPUT_FOLDER/yukino-net-armhf.deb

rm -rf pkg-build
rm -rf build
