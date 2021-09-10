#!/bin/bash

CA_SUBJECT="/C=US/ST=CA/L=Sunnyvale/O=Yukino App./CN=Yukino Root CA"
CERT_SUBJECT="/C=US/ST=CA/L=Sunnyvale/O=Yukino App./CN=Yukino"

if [ ! -f ca.key ]; then
	openssl genrsa -out ca.key 8192
	openssl req -new -x509 -days 3650 -key ca.key -subj "$CA_SUBJECT" -out ca.crt
else
	echo Skiping CA generation.
fi

generate_cert_and_sign() {
	if [ -f $1.key ]; then
		echo Skiping $1.key
		return
	fi
	echo Generating $1.key...
	openssl req -newkey rsa:4096 -nodes -keyout $1.key -subj "$CERT_SUBJECT $2" -out $1.csr
	openssl x509 -req -extfile <(printf "subjectAltName=DNS:$3") -days 365 -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt
}

generate_cert_and_sign server Server message.yukino.app
generate_cert_and_sign proxy Proxy proxy.yukino.app
generate_cert_and_sign shell Shell shell.yukino.app