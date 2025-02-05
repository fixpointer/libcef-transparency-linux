all: patcher_lib.so


proc_maps_parser:
	git clone https://github.com/ouadev/proc_maps_parser

proc_maps_parser/build/libpmparser.a: proc_maps_parser
	cd proc_maps_parser && $(MAKE)

patcher_lib.so: patcher_lib.c proc_maps_parser/build/libpmparser.a
	gcc -masm=intel -Iproc_maps_parser/include -o patcher_lib.so -shared -fpic -z defs patcher_lib.c -lc -l:libpmparser.a -L./proc_maps_parser/build


clean:
	rm patcher_lib.so || true
	rm -rf proc_maps_parser || true
