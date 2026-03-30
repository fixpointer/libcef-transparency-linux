// #define _GNU_SOURCE

#include <link.h>
#include <libgen.h>
extern "C" {
#include <pmparser.h>
}

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <dlfcn.h>

#include <optional>
#include <span>

using std::span;

#define nitems(x) (sizeof(x)/sizeof((x)[0]))

char** get_argv(void* stack_start, void* stack_end, int* argc_out) {
    uint8_t* cur = (uint8_t*) environ;

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

/**
 * Find a `needle` in `haystack` where the bytes match after applying needle_mask
 */
std::optional<span<uint8_t>> masked_memfind(span<uint8_t> needle, span<uint8_t> haystack, span<uint8_t> needle_mask) {
    for (size_t offset = 0; offset < haystack.size() - needle.size(); offset++) {
        for (size_t i = 0; i < needle.size(); ) {
            if (needle.size() - i > 8 && (uintptr_t)haystack.data() & 0x7 == 0) { 
                if (*(uint64_t*)(haystack.data() + offset + i) & *(uint64_t*)(needle_mask.data()+i)
                != *(uint64_t*)(needle.data() + i) & *(uint64_t*)(needle_mask.data() + i) 
                ) goto not_found;

                i += 8;
            } else {
                if ((haystack[offset+i] & needle_mask[i]) != (needle[i] & needle_mask[i])) goto not_found;
                i += 1;
            }
            
        }
        return std::optional(span(haystack.data()+offset, needle.size()));
        not_found:
    }
    return std::optional<span<uint8_t>>{};
}

span<uint8_t> span_page_align(span<uint8_t> sp) {
    return {
        (uint8_t*)( (uintptr_t) sp.data() & ~0xfffull),
        (uint8_t*)( (uintptr_t) sp.data() + sp.size() + 0xfff & ~0xfffull)
    };
}

int mprotect_span(span<uint8_t> data, int prot) {
    auto pa = span_page_align(data);
    return mprotect(pa.data(), pa.size(), prot);
}

unsigned int la_version(unsigned int version) {

    procmaps_error_t parser_err;
    procmaps_iterator maps = {0};
    parser_err = pmparser_parse(-1, &maps);

    if (parser_err != PROCMAPS_SUCCESS) {
        fprintf(stderr, "[aero_patcher]: could not parse memory maps. no patch applied\n");
        pmparser_free(&maps);
        return LAV_CURRENT;
    }

    procmaps_struct *mem_region;

    char imagename_buf[256];
    size_t imagename_len;

    if ((imagename_len = readlink("/proc/self/exe", imagename_buf, 256)) == (size_t) -1) {
        fprintf(stderr, "[aero_patcher]: could not read /proc/self/exe\n");
        pmparser_free(&maps);
        return LAV_CURRENT;
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
        pmparser_free(&maps);
        return LAV_CURRENT;
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
        uint8_t* result = (uint8_t*) memmem(search_start, (uintptr_t) main_text->addr_end - (uintptr_t) search_start, "\x12\x12\x12\xff", 4);

        if (!result) break;

        bool prefix_valid = false;



        // check for match with one of the allowed prefixes
        for (unsigned int i = 0; i < nitems(allowed_prefixes) && !prefix_valid; i++) {
            uint64_t tmp = *(uint64_t*) (result-8);
            tmp &= *(uint64_t*)allowed_prefixes[i].mask;

            if (tmp == *(uint64_t*) allowed_prefixes[i].value) prefix_valid = true;

        }
        if (prefix_valid) {
            if (mprotect((void*)((uintptr_t)result & ~0xfffULL), ((uintptr_t) result & 0xfff) > 0x1000-4 ? 0x2000: 0x1000, PROT_WRITE | PROT_READ) == -1) {
                perror("[aero_patcher]: mprotect failure\n");
                pmparser_free(&maps);
                return LAV_CURRENT;
            }

            fprintf(stderr, "[aero_patcher] found color patch pattern 121212ff @ %p\n", result);
            memcpy(result,"\x00\x00\x00\x00", 4);

            if (mprotect((void*)((uintptr_t)result & ~0xfffULL), ((uintptr_t) result & 0xfff) > 0x1000-4 ? 0x2000: 0x1000, PROT_EXEC | PROT_READ) == -1) {
                perror("[aero_patcher]: mprotect failure\n");
                pmparser_free(&maps);
                return LAV_CURRENT;
            }
        }




        //fprintf(stderr, "[aero_patcher] successfully patched text offset 0x%lx\n", (uintptr_t) result - (uintptr_t)(main_text->addr_start));
        search_start = result+4;

        if ((uint8_t*) search_start + 4 >= main_text->addr_end) break;
    }

    // free function is safe even if pointer is null
    pmparser_free(&maps);
    return LAV_CURRENT;
}

uint8_t patch_pattern_wincreate[] = {
    // mov eax, [r14+0x18]
    0x41, 0x8b, 0x46, 0x18,

    // test eax, eax
    0x85, 0xc0,

    // jz 1f
    0x74, 0x0a,

    // cmp eax, 2
    0x83, 0xf8, 0x02,

    // jz 2f
    0x74, 0x0f,

    // xor r12d, r12d
    0x45, 0x31, 0xe4,

    // jmp 3f
    0xeb, 0x0d,

    // cmp dword ptr [r14], 4
    0x41, 0x83, 0x3e, 0x04,

    // setz r12b
    0x41, 0x0f, 0x94, 0xc4,

    // jmp 3f
    0xeb, 0x03,

    // mov r12b, 1
    0x41, 0xb4, 0x01
};

// comparison masks for mod r/m byte to allow any reg either in "r" only or in "r/m", with fixed mod of 3 (immediate register, no memory access)
const uint8_t MODRM_ANY_R_MASK = 0xc7;
const uint8_t MODRM_ANY_M_MASK = 0xf8;
const uint8_t MODRM_ANY_RM_MASK = 0xc0;


uint8_t patch_pattern_wincreate_mask[] = {
    // mov eax, [r14+0x18]
    0xff,0xff,0xff,0xff,

    // test eax, eax
    0xff,0xff,

    // jz 1f
    0xff,0xff,

    // cmp eax, 2
    0xff,0xff,0xff,

    // jz 2f
    0xff,0xff,

    // xor r12d, r12d - REX prefix, opcode, mod r/m byte
    0xff,0xff, MODRM_ANY_RM_MASK,

    // jmp 3f
    0xff,0xff,

    // cmp dword ptr [r14], 4
    0xff,0xff,0xff,0xff,

    // setz r12b - REX prefix, 2-byte opcode escape, opcode, mod r/m byte with r fixed to 0 (and r/m specifying register)
    0xff, 0xff, 0xff, MODRM_ANY_M_MASK,

    // jmp 3f
    0xff, 0xff,

    // mov r12b, 1 - REX prefix, base opcode b0 | reg, immediate
    0xff, 0xf8, 0xff
};



/**
 * Find the code in libcef that is responsible for handling X11 window transparency and patch it to request all windows to be transparent
 * 
 * @returns if the patch has been found and applied successfully
 */
bool apply_libcef_transparency_patch(span<uint8_t> libcef_text, void* libcef_baseaddr) {
    if (auto res = masked_memfind(patch_pattern_wincreate, libcef_text, patch_pattern_wincreate_mask )) {
        span<uint8_t> patch_destination = *res;


        // get the register number used for the register holding the transparency flag
        uint8_t transparency_flag_reg = patch_destination[0xf] & 7;

        fprintf(stderr, "[aero_patcher] reg r%d\n", 8+transparency_flag_reg);

        if (mprotect_span(patch_destination,PROT_WRITE | PROT_READ)
            == -1) {
            perror("[aero_patcher]: mprotect failure");
            return false;
        }


        fprintf(stderr, "[aero_patcher] found x11 transparency flag handling code @ %p (offset %lx). will apply patch of length %ld\n", patch_destination.data(), patch_destination.data() - (uint8_t*)libcef_baseaddr, patch_destination.size());


        memset(patch_destination.data(), '\x90', patch_destination.size());


        // mov <reg>, 1
        uint8_t patch[] = {0x41, (uint8_t)( 0xb0 | transparency_flag_reg), 0x01};
        memcpy(patch_destination.data(),patch, sizeof(patch));



        if (mprotect_span(patch_destination,  PROT_READ | PROT_EXEC)
            == -1) {
            perror("[aero_patcher]: mprotect failure");
            return false;
        }
        return true;

    } else { return false;}


}

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
        pmparser_free(&maps);
        return LAV_CURRENT;
    }

    procmaps_struct *mem_region;
    procmaps_struct *libcef_text = NULL;
    procmaps_struct *libcef_base = NULL;

    while ((mem_region = pmparser_next(&maps)) != NULL) {
        if (!strcmp(mem_region->pathname, map->l_name)) {
            if (!libcef_base) libcef_base = mem_region;
            if (mem_region->is_x) {
                libcef_text = mem_region;
                break;
            }
        }
    }

    if (!libcef_text) {
        fprintf(stderr, "[aero_patcher] could not find libcef text\n");
        pmparser_free(&maps);
        return LAV_CURRENT;
    }

    if (!apply_libcef_transparency_patch(span<uint8_t>((uint8_t*)libcef_text->addr_start, (uint8_t*) libcef_text->addr_end), libcef_base->addr_start)) {
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
            cef_version_info = (char*)memmem(rodata->addr_start, rodata->length,"+chromium-",10);

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

        pmparser_free(&maps);
        return LAV_CURRENT;
    }


    fprintf(stderr, "[aero_patcher] have successfully patched libcef\n");

    // free function is safe even if pointer is null
    pmparser_free(&maps);
    return 0;
}


