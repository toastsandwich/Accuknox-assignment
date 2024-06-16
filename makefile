TARGET = droper
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

pre:
	@echo getting packages...
	@go mod tidy

%.bpf.o: %.bpf.c
	@echo compiling...
	@clang -g -O2 --target=bpf -D __TARGET_ARCH_$(ARCH) -Wall -o $@ -c $<

obj:
	@echo "generating obj files.."
	@go generate

clean:
	@echo cleaning...
	@rm droper_*.go
	@rm droper_*.o

build: pre obj
	@echo building...
	@go build .

run: build
	@echo build success, program loaded
	@go run droper.userspace.go
