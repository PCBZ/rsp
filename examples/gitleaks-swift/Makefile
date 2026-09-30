# SwiftPM is the build; this is here so `make test` means the same thing in
# every adapter. JSON comes from Foundation, so nothing is downloaded.
.PHONY: all test clean
all:
	swift build -c release

test: all
	.build/release/offset-test
	./testdata/requests.sh .build/release/rsp-gitleaks-swift

clean:
	swift package clean
	rm -rf .build
