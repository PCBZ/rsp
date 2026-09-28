# cJSON comes from the system, not from this repository: it is 3512 lines
# against a core of 854, and vendoring it would make this repo responsible for
# tracking someone else's fixes. brew install cjson / apt-get install libcjson-dev
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror
PREFIX ?= $(shell brew --prefix 2>/dev/null)
CFLAGS += $(if $(PREFIX),-I$(PREFIX)/include)
LDFLAGS += $(if $(PREFIX),-L$(PREFIX)/lib)
LDLIBS = -lcjson

rsp-gitleaks-c: main.o protocol.o gitleaks.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-gitleaks: test_gitleaks.o protocol.o gitleaks.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

main.o protocol.o gitleaks.o test_gitleaks.o: gitleaks.h protocol.h

.PHONY: test clean
test: test-gitleaks
	./test-gitleaks

clean:
	rm -f rsp-gitleaks-c test-gitleaks *.o
