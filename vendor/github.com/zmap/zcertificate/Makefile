all: zcertificate

cmd/zcertificate/zcertificate:
	cd cmd/zcertificate && go build

zcertificate: cmd/zcertificate/zcertificate
	cp $< zcertificate

.PHONY: cmd/zcertificate/zcertificate zcertificate clean test

clean:
	rm -f cmd/zcertificate/zcertificate zcertificate

test:
	go test ./...
