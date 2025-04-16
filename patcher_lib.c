#define _GNU_SOURCE
#include <link.h>
#include <libgen.h>
#include <pmparser.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <dlfcn.h>


#define nitems(x) (sizeof(x)/sizeof((x)[0]))

char** get_argv(void* stack_start, void* stack_end, int* argc_out) {
    void* cur = environ;

    // walk backwards from the environ ptr to find the pointer to the program stack base,
    // which is before the argv and easily identifiable because it points to itself + 8
    while(!(*(uintptr_t*) cur == (uintptr_t) cur + 8)) {
        cur -= 8;
        if (cur < stack_start) return NULL;
    }

    // skip the pointer-to-base and 8 bytes of alignment junk
    // depending on the initial stack alignment, we now point either to the argc or directly to argv[0]
    cur += 16;

    // all actual argv and env strings are stored on the stack - if the value we are currently pointing to
    // does not look like a stack pointer, it's probably the argc
    if (*(uintptr_t*) cur < (uintptr_t) stack_start || *(uintptr_t*) cur >= (uintptr_t) stack_end)
        cur += 8;

    if (*(uintptr_t*) cur >= (uintptr_t) stack_start && *(uintptr_t*) cur < (uintptr_t) stack_end) {
        // we know that the envp array is directly behind the argv array, separated with a null qword
        if (argc_out)
            *argc_out = ((uintptr_t) environ - 8 - (uintptr_t) cur) / 8;

        return (char**) cur;

    }

    return NULL;
}

unsigned int la_version(unsigned int version) {

    procmaps_error_t parser_err;
    procmaps_iterator maps = {0};
    parser_err = pmparser_parse(-1, &maps);

    if (parser_err != PROCMAPS_SUCCESS) {
        fprintf(stderr, "[aero_patcher]: could not parse memory maps. no patch applied\n");
        goto free_pm_and_return;
    }

    procmaps_struct *mem_region;

    char imagename_buf[256];
    size_t imagename_len;

    if ((imagename_len = readlink("/proc/self/exe", imagename_buf, 256)) == -1) {
        fprintf(stderr, "[aero_patcher]: could not read /proc/self/exe\n");
        goto free_pm_and_return;
    }

    imagename_buf[imagename_len] = 0;
    procmaps_struct *main_text = NULL;

    while ((mem_region = pmparser_next(&maps)) != NULL) {
        // fprintf(stderr, "spotify main text candidate: pathname=%s,selfexe=%s, is_x=%d\n", mem_region->pathname, imagename_buf, mem_region->is_x);
        if (!strcmp(mem_region->pathname, imagename_buf) && mem_region->is_x && !mem_region->is_w) {
            main_text = mem_region;
            break;
        }
    }

    if (!main_text) {
        fprintf(stderr, "[aero_patcher]: could not determine main executable region. no patch applied\n");
        goto free_pm_and_return;
    }


    //fprintf(stderr, "[aero_patcher]: have main text from %p to %p\n", main_text->addr_start, main_text->addr_end);
    void* search_start = main_text->addr_start;

    // allowed values (with masks) for the 8 bytes before the match
    // There may be some other instruction that contains the bytes 12 12 12 ff in its encoding, and when we patch those, we will crash
    // Therefore, we try to match on the complete instruction that contains the immediate value, and check whether it matches one of the expected
    // occurrences, either a move of the 32-bit immediate directly into a register, or a move into memory pointed to by a register with a small displacement
    // (i.e. where the value is moved into a struct)
    struct {
        uint8_t* value;
        uint8_t* mask;
    } allowed_prefixes [] = {
        {
            .value = (uint8_t*)"\x00\x00\xc7\x80\x00\x00\x00\x00",

            // force match on opcode (c7), and mode / op parts of modrm byte, and lower 12 bits of address
            // this should still catch the mov if the register or struct offset changes slightly, but avoid matching anything entirely different
            .mask  = (uint8_t*)"\x00\x00\xff\xf8\x00\xf0\xff\xff"
        },
        {
            .value = (uint8_t*) "\x00\x00\x00\x00\x00\x00\x00\xb8",
            // match mov <register>, <32 bit immediate> for any register
            .mask = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\xf8"
        }
    };

    while(true) {
        void* result = memmem(search_start, (uintptr_t) main_text->addr_end - (uintptr_t) search_start, "\x12\x12\x12\xff", 4);

        if (!result) break;

        bool prefix_valid = false;



        // check for match with one of the allowed prefixes
        for (int i = 0; i < nitems(allowed_prefixes) && !prefix_valid; i++) {
            uint64_t tmp = *(uint64_t*) (result-8);
            tmp &= *(uint64_t*)allowed_prefixes[i].mask;

            if (tmp == *(uint64_t*) allowed_prefixes[i].value) prefix_valid = true;

        }
        if (prefix_valid) {
            if (mprotect((void*)((uintptr_t)result & ~0xfffULL), ((uintptr_t) result & 0xfff) > 0x1000-4 ? 0x2000: 0x1000, PROT_WRITE | PROT_READ) == -1) {
                perror("[aero_patcher]: mprotect failure\n");
                goto free_pm_and_return;
            }

            fprintf(stderr, "[aero_patcher] found color patch pattern 121212ff @ %p\n", result);
            memcpy(result,"\x00\x00\x00\x00", 4);

            if (mprotect((void*)((uintptr_t)result & ~0xfffULL), ((uintptr_t) result & 0xfff) > 0x1000-4 ? 0x2000: 0x1000, PROT_EXEC | PROT_READ) == -1) {
                perror("[aero_patcher]: mprotect failure\n");
                goto free_pm_and_return;
            }
        }




        //fprintf(stderr, "[aero_patcher] successfully patched text offset 0x%lx\n", (uintptr_t) result - (uintptr_t)(main_text->addr_start));
        search_start = result+4;

        if (search_start + 4 >= main_text->addr_end) break;
    }

    free_pm_and_return:

    // free function is safe even if pointer is null
    pmparser_free(&maps);
    return LAV_CURRENT;
}

__attribute__((naked)) void __patch_pattern() {
    asm volatile(
        "patch_pattern_start: mov eax, [r14+0x18];"
        "test eax, eax;"
        "jz 1f;"
        "cmp eax, 2;"
        "jz 2f;"
        "xor r13d, r13d;"
        "jmp 3f;"
        "1: cmp dword ptr [r14], 4;"
        "setz r13b;"
        "jmp 3f;"
        "2: mov r13b,1;"
        "3: patch_pattern_end: nop"
    );
}

__attribute__((naked)) void __patch() {
    asm volatile(
        "patch_start: mov r13d, 1; patch_end: nop"
    );
}

void patch_pattern_start(void);
void patch_pattern_end(void);

void patch_start(void);
void patch_end(void);


unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t *cookie) {
    char* path = strdup(map->l_name);
    if (!strcmp(basename(path), "libcef.so")) {
        //printf("[aero_patcher]: have found libcef.so at base addr 0x%lx\n", map->l_addr);
    } else {
        return 0;
    }

    procmaps_error_t parser_err;
    procmaps_iterator maps = {0};
    parser_err = pmparser_parse(-1, &maps);

    if (parser_err != PROCMAPS_SUCCESS) {
        fprintf(stderr, "[aero_patcher]: could not parse memory maps. no patch applied\n");
        goto free_pm_and_return;
    }

    procmaps_struct *mem_region;
    procmaps_struct *libcef_text = NULL;

    while ((mem_region = pmparser_next(&maps)) != NULL) {
        if (!strcmp(mem_region->pathname, map->l_name) && mem_region->is_x) {
            libcef_text = mem_region;
            break;
        }
    }

    if (!libcef_text) {
        fprintf(stderr, "[aero_patcher] could not find libcef text\n");
        goto free_pm_and_return;
    }

    void* patch_destination = memmem(libcef_text->addr_start, libcef_text->length,
                                     patch_pattern_start, (uintptr_t) patch_pattern_end - (uintptr_t) patch_pattern_start);

    if (!patch_destination) {
        fprintf(stderr, "[aero_patcher] could not find libcef patch pattern. This may happen when Spotify updates their libcef");
        fprintf(stderr, "[aero_patcher] please file an issue on GitHub and provide the following information: \n");

        char* cef_version_info = NULL;

        maps.current=maps.head;

        procmaps_struct *rodata = NULL;
        while((mem_region=pmparser_next(&maps)) != NULL) {
            if (!strcmp(mem_region->pathname, map->l_name) && !mem_region->is_x && !mem_region->is_w) {
                rodata = mem_region;
                break;
            }
        }

        if (rodata) {
            cef_version_info = memmem(rodata->addr_start, rodata->length,"+chromium-",10);

            if (cef_version_info) {
                while(*cef_version_info) cef_version_info--;
                cef_version_info++;
            }
        }
        if (cef_version_info) {
            fprintf(stderr,"CEF version: %s\n",cef_version_info);
        } else {
            fprintf(stderr,"<cef information readout fail>\n");
        }

        fprintf(stderr, "[aero_patcher] if possible, also upload your libcef.so (found under %s) somewhere and provide a link in the issue\n", map->l_name);

        goto free_pm_and_return;
    }

    if (mprotect(
            (void*)((uintptr_t)patch_destination & ~0xfffULL),
            ((uintptr_t)patch_destination & 0xfff) > 0x1000-4 ? 0x2000: 0x1000,
            PROT_WRITE | PROT_READ)
        == -1) {
        perror("[aero_patcher]: mprotect failure");
        goto free_pm_and_return;
    }

    size_t patch_len = (uintptr_t) patch_end - (uintptr_t) patch_start;
    size_t patch_pattern_len = (uintptr_t) patch_pattern_end - (uintptr_t) patch_pattern_start;


    fprintf(stderr, "[aero_patcher] found x11 transparency flag handling code @ %p. will apply patch of length %ld\n", patch_destination, patch_pattern_len);


    memset(patch_destination, '\x90', patch_pattern_len);
    memcpy(patch_destination,(void*)patch_start, patch_len);



    if (mprotect(
            (void*)((uintptr_t)patch_destination & ~0xfffULL),
            ((uintptr_t)patch_destination & 0xfff) > 0x1000-4 ? 0x2000: 0x1000,
            PROT_EXEC | PROT_READ)
        == -1) {
        perror("[aero_patcher]: mprotect failure");
        goto free_pm_and_return;
    }

    fprintf(stderr, "[aero_patcher] have successfully patched libcef\n");

    free_pm_and_return:

    // free function is safe even if pointer is null
    pmparser_free(&maps);
    return 0;
}


