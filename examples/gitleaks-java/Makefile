# gson comes from Maven Central rather than this tree, pinned and checksummed
# the way the workflow pins gitleaks. Java has no JSON in its standard library.
GSON_VERSION ?= 2.11.0
GSON_SHA = 57928d6e5a6edeb2abd3770a8f95ba44dce45f3b23b7a9dc2b309c581552a78b
GSON = lib/gson-$(GSON_VERSION).jar
JAVAC ?= javac
JAVA ?= java

# An executable launcher, so the conformance kit can tell a built adapter from
# an unbuilt one the way it does for the C and Go binaries.
rsp-gitleaks-java: classes/Main.class
	printf '#!/bin/sh\nexec "%s" -cp "%s:%s" Main "$$@"\n' \
	    "$(JAVA)" "$(CURDIR)/classes" "$(CURDIR)/$(GSON)" > $@
	chmod +x $@

classes/Main.class: $(wildcard src/*.java) $(GSON)
	mkdir -p classes
	$(JAVAC) -Xlint:all,-classfile -Werror -cp $(GSON) -d classes src/*.java

# Verified before it is put where the build looks: make does not delete a
# target whose recipe failed, so checking in place would leave a rejected jar
# that the next make finds present and does not check again.
$(GSON):
	mkdir -p lib
	curl -sSfL -o $@.unverified \
	    https://repo1.maven.org/maven2/com/google/code/gson/gson/$(GSON_VERSION)/gson-$(GSON_VERSION).jar
	echo "$(GSON_SHA)  $@.unverified" | shasum -a 256 --check --strict - || { rm -f $@.unverified; exit 1; }
	mv $@.unverified $@

.PHONY: test clean
test: rsp-gitleaks-java
	$(JAVAC) -Xlint:all,-classfile -Werror -cp "classes:$(GSON)" -d classes test/*.java
	$(JAVA) -cp "classes:$(GSON)" GitleaksTest
	./testdata/requests.sh ./rsp-gitleaks-java

clean:
	rm -rf classes rsp-gitleaks-java
