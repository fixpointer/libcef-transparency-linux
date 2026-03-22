all: patcher_lib.so

CFLAGS := -g -O3 -Wall -Wno-parentheses -masm=intel -Iproc_maps_parser/include  -shared -fpic -z defs
CXXFLAGS := -std=c++23
proc_maps_parser:
	git clone https://github.com/ouadev/proc_maps_parser

proc_maps_parser/build/libpmparser.a: proc_maps_parser
	cd proc_maps_parser && $(MAKE)

patcher_lib.so: patcher_lib.cc proc_maps_parser/build/libpmparser.a
	# link against static libpmparser, build a shared library
	$(CXX) $(CFLAGS) $(CXXFLAGS) -o patcher_lib.so patcher_lib.cc -lc -l:libpmparser.a -L./proc_maps_parser/build


clean:
	rm patcher_lib.so || true
	rm -rf proc_maps_parser || true

install:
	cp patcher_lib.so /usr/share/spotify