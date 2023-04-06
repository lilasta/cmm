cmm: cmm.c
	cc -o cmm cmm.c

run: cmm
	./cmm run.cmm

clean:
	rm -f ./cmm

.PHONY: run clean
