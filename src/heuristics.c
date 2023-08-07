#include <stdbool.h>

#include "heuristics.h"
#include "a64.h"

uint32_t g_externalMethod_idx = -1;
uint32_t g_externalMethod2_idx = -1;
uint32_t g_getTargetAndMethodForIndex_idx = -1;
kptr_t g_dispatchExternalMethod_addr = 0;

mach_hdr_t* fileset_macho_get_kext(mach_hdr_t* kernel, const char* fsent_name) {
    FOREACH_CMD(kernel, cmd) {
        if(cmd->cmd == LC_FILESET_ENTRY) {
            mach_fileent_t *ent = (mach_fileent_t*)cmd;
            mach_hdr_t *mh = (void*)((uintptr_t)kernel + ent->fileoff);
            const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
            if (strcmp(name, fsent_name) == 0) {
                return mh;
            }
        }
    }
    return NULL;
}

mach_sec_t* hdr_get_section(mach_hdr_t* hdr, const char* segname, const char* sectname) {
    if (!hdr)
        return NULL;

    FOREACH_CMD(hdr, cmd) {
        if(cmd->cmd == MACH_SEGMENT) {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if (strncmp(seg->segname, segname, sizeof(seg->segname)) == 0) {
                // found segment
                mach_sec_t *sect = (mach_sec_t*)(seg + 1);
                for (uint32_t i = 0;
                    i < seg->nsects;
                    i++, sect++)
                {
                    if (!strcmp(sect->sectname, sectname)) {
                        return sect;
                    }
                }
                break;
            }
        }
    }
    return NULL;
}

const char* start_of_string(const char* s) {
    while (*(s - 1)) { s--; }
    return s;
}

int find_externalMethod_idx(void* kernel, metaclass_t* IOUserClient, metaclass_t* IOUserClient2022, uint32_t* out_idx) {
    for (size_t meth_idx = 0; meth_idx < IOUserClient->nmethods; meth_idx++) {
        vtab_entry_t* meth = &IOUserClient->methods[meth_idx];
        // easiest option is if we have symbols:
        const char namematch[] = "externalMethod(";
        if (meth->method && strncmp(meth->method, namematch, sizeof(namematch) - 1) == 0) {
            *out_idx = meth_idx;
            return 0;
        }
    }

    // second easiest option is if we have IOUserClient2022:
    if (IOUserClient2022) {
        // find string:
        const char match_string[] = "wrong externalMethod for IOUserClient2022";
        mach_hdr_t* hdr = (mach_hdr_t*)kernel;
        mach_hdr_t* kernel_header = hdr->filetype == MH_FILESET ? fileset_macho_get_kext(hdr, "com.apple.kernel") : hdr;
        mach_sec_t* text_cstring = hdr_get_section(kernel_header, "__TEXT", "__cstring");
        if (!text_cstring) {
            ERR("Failed to find com.apple.kernel:__TEXT.__cstring section.");
            return 1;
        }
        void* range = (void*)((uintptr_t)kernel_header + text_cstring->offset);
        const char* found_str = start_of_string(memmem(range, text_cstring->size, match_string, sizeof(match_string) - 1));
        kptr_t str_addr = off2addr(kernel, (uintptr_t)found_str - (uintptr_t)kernel);
        
        // find string load:
        kptr_t str_load_addr = 0;
        mach_sec_t* text = hdr_get_section(kernel_header, "__TEXT_EXEC", "__text");
        if (!text) {
            ERR("Failed to find com.apple.kernel:__TEXT_EXEC.__text section.");
            return 1;
        }
        uint32_t* insn = (uint32_t*)((uintptr_t)kernel_header + text->offset);
        for (; insn < (uint32_t*)((uintptr_t)kernel_header + text->offset + text->size - sizeof(uint32_t)); insn++) {
            adr_t* adr = (adr_t*)insn;
            add_imm_t* add = (add_imm_t*)(insn + 1);
            if (is_adrp(adr) && is_add_imm(add)) {
                kptr_t adr_addr = off2addr(kernel, (uintptr_t)adr - (uintptr_t)kernel);
                kptr_t load_addr = (adr_addr & ~0xfff) + get_adr_off(adr) + get_add_sub_imm(add);
                if (load_addr == str_addr) {
                    str_load_addr = adr_addr;
                    break;
                }
            }
        }

        // find vtable method closest to load insn:
        uint32_t best_idx = -1;
        uint64_t best_off = UINT64_MAX;
        for (size_t i = 0; i < IOUserClient2022->nmethods; i++) {
            vtab_entry_t* meth = &IOUserClient2022->methods[i];
            if (meth->addr < str_load_addr && (str_load_addr - meth->addr) < best_off) {
                best_off = str_load_addr - meth->addr;
                best_idx = i;
            }
        }

        if (best_idx != -1) {
            *out_idx = best_idx;
            return 0;
        }
    }

    // backwards compatibility never bothered me anyway
    return 1;
}

int find_getTargetAndMethodForIndex_idx(void* kernel, metaclass_t* IOUserClient, uint32_t* out_idx) {
    for (size_t meth_idx = 0; meth_idx < IOUserClient->nmethods; meth_idx++) {
        vtab_entry_t* meth = &IOUserClient->methods[meth_idx];
        // easiest option is if we have symbols:
        const char namematch[] = "getTargetAndMethodForIndex(";
        if (meth->method && strncmp(meth->method, namematch, sizeof(namematch) - 1) == 0) {
            *out_idx = meth_idx;
            return 0;
        }
    }

    // instead, we look for the reference in IOUserClient::externalMethod:
    /*
    LDR             X10, [X16,#0x970]
    ADD             X1, SP, #0x50+var_38    ; targetP
    MOV             X0, X8                  ; this
    MOV             X17, X9
    MOVK            X17, #0xBDAA,LSL#48
    BLRAA           X10, X17                ; IOUserClient::getTargetAndMethodForIndex
    */
    #define TARGET_DIVERSIFIER 0xBDAA
    if (g_externalMethod_idx != -1) {
        uint32_t* externalMethod = (uint32_t*)addr2ptr(kernel, IOUserClient->methods[g_externalMethod_idx].addr);
        uint32_t* externalMethod_end = externalMethod + 0x100;
        add_imm_t* lastAdd = NULL;
        blr_t* targetBlr = NULL;
        for (uint32_t* insn = externalMethod; insn < externalMethod_end; insn++) {
            add_imm_t* add = (add_imm_t*)insn;
            blr_t* blr = (blr_t*)insn;
            if (is_add_imm(add) && add->Rd == 1 && add->Rn == 31) { // ADD X1, SP, ...
                lastAdd = add;
            } else if (is_blr(blr)) {
                if (blr->A) {
                    // authenticated branch, check PAC diversifier:
                    movk_t* movk = (movk_t*)(blr - 1);
                    if (is_movk(movk) && movk->Rd == blr->Rm && movk->sf == 1 && movk->imm == TARGET_DIVERSIFIER) {
                        targetBlr = blr;
                        break;
                    }
                } else {
                    // unauthenticated, just look for the stack reference:
                    if (lastAdd && (uint32_t*)blr - (uint32_t*)lastAdd < 10) {
                        targetBlr = blr;
                        // getAsyncTargetAndMethodForIndex comes first, so we find the last occurence
                    }
                }
            }
        }

        if (!targetBlr) {
            ERR("Failed to find BLR[AA] to getTargetAndMethodForIndex.");
            return 1;
        }

        // search backwards to find vtable offset:
        for (uint32_t* insn = (uint32_t*)targetBlr; insn >= externalMethod; insn--) {
            ldr_imm_uoff_t* ldr = (ldr_imm_uoff_t*)insn;
            if (is_ldr_imm_uoff(ldr) && ldr->Rt == targetBlr->Rn) {
                uint32_t off = get_ldr_imm_uoff(ldr);
                *out_idx = off / 8;
                return 0;
            }
        }
    }
    return 1;
}

int find_externalMethod2_idx(void* kernel, metaclass_t* IOUserClient2022, metaclass_t** clients2022, size_t clients2022_count, uint32_t* out_idx) {
    // pure virtual in IOUserClient2022, so find it in one of the subclasses:
    // I'm choosing IOSurfaceRootUserClient:
    metaclass_t* IOSurfaceRootUserClient = NULL;
    for (metaclass_t** client = clients2022; client < clients2022 + clients2022_count; client++) {
        if (strcmp((*client)->name, "IOSurfaceRootUserClient") == 0) {
            IOSurfaceRootUserClient = *client;
            break;
        }
    }
    if (!IOSurfaceRootUserClient) {
        ERR("Failed to find IOSurfaceRootUserClient metaclass.");
        return 1;
    }

    for (int meth_idx = IOSurfaceRootUserClient->nmethods - 1; meth_idx >= 0; meth_idx--) {
        vtab_entry_t* meth = &IOSurfaceRootUserClient->methods[meth_idx];
        // easiest option is if we have symbols:
        const char namematch[] = "externalMethod(";
        if (meth->method && meth->overrides && strncmp(meth->method, namematch, sizeof(namematch) - 1) == 0) {
            *out_idx = meth_idx;
            return 0;
        }
    }

    // it's gonna be near the end, so search backwards:
    for (int i = IOSurfaceRootUserClient->nmethods - 1; i >= 0; i--) {
        if (!IOSurfaceRootUserClient->methods[i].overrides)
            continue;

        // we are looking for 4 things:
        // 1. function is small
        // 2. ADRL
        // 3. MOV w4, #...
        // 4. Ends in B ...
        bool found_adrl = false;
        bool found_mov = false;

        uint32_t* fn = addr2ptr(kernel, IOSurfaceRootUserClient->methods[i].addr);
        uint32_t* fn_end = fn + 0x10;
        for (uint32_t* insn = fn; insn < fn_end; insn++) {
            if (is_adrp((adr_t*)insn) && is_add_imm((add_imm_t*)(insn + 1))) {
                found_adrl = true;
            } else {
                movz_t* mov = (movz_t*)insn;
                if (is_movz(mov) && mov->Rd == 4) {
                    found_mov = true;
                } else if (is_b((b_t*)insn)) {
                    if (!found_mov || !found_adrl)
                        break; // wrong function, try the next
                    *out_idx = i;
                    return 0;
                }
            }
        }
    }
    return 1;
}

int find_dispatchExternalMethod_addr(void* kernel, metaclass_t* IOUserClient2022, sym_t* bsyms, size_t nsyms, metaclass_t** clients2022, size_t clients2022_count, kptr_t* out_addr) {
    // easiest option is if we have symbols:
    if (nsyms > 0) {
        kptr_t addr = find_sym_by_name("__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv", bsyms, nsyms);
        if (addr) {
            *out_addr = addr;
            return 0;
        }
    }

    // otherwise, we just look for what function a subclass branches to in ::externalMethod:
    // I'm choosing IOSurfaceRootUserClient::externalMethod:
    // this makes the assumption that the kexts are all pre-linked, so we don't go through __got
    if (g_externalMethod2_idx != -1) {
        metaclass_t* IOSurfaceRootUserClient = NULL;
        for (metaclass_t** client = clients2022; client < clients2022 + clients2022_count; client++) {
            if (strcmp((*client)->name, "IOSurfaceRootUserClient") == 0) {
                IOSurfaceRootUserClient = *client;
                break;
            }
        }
        if (!IOSurfaceRootUserClient) {
            ERR("Failed to find IOSurfaceRootUserClient metaclass.");
            return 1;
        }
            
        uint32_t* externalMethod = (uint32_t*)addr2ptr(kernel, IOSurfaceRootUserClient->methods[g_externalMethod2_idx].addr);
        uint32_t* externalMethod_end = externalMethod + 0x10;
        for (uint32_t* insn = externalMethod; insn < externalMethod_end; insn++) {
            if (is_b((b_t*)insn) || is_bl((bl_t*)insn)) {
                kptr_t addr = off2addr(kernel, (uintptr_t)insn - (uintptr_t)kernel);
                *out_addr = addr + get_bl_off((bl_t*)insn);
                return 0;
            }
        }
    }
    return 1;
}

int find_client2022_nmethods(void* kernel, metaclass_t* meta, int* out_nmethods) {
    // get externalMethod:
    if (g_externalMethod2_idx >= meta->nmethods)
        return 1;
    vtab_entry_t* meth = &meta->methods[g_externalMethod2_idx];
    if (!meth->overrides)
        return 1;
    uint32_t* fn = (uint32_t*)addr2ptr(kernel, meth->addr);
    uint32_t* fn_end = fn + 0x80;
    if (!fn)
        return 1;
    
    // find store to w4:
    int nmethods = -1;
    for (uint32_t* insn = fn; insn < fn_end; insn++) {
        movz_t* mov = (movz_t*)insn;
        bl_t* bl = (bl_t*)insn;
        if (is_movz(mov) && mov->Rd == 4) {
            nmethods = get_movzk_imm(mov);
        } else if (is_b((b_t*)bl) || is_bl(bl)) {
            kptr_t target = off2addr(kernel, (uintptr_t)bl - (uintptr_t)kernel) + get_bl_off(bl);
            if (target == g_dispatchExternalMethod_addr) {
                if (nmethods == -1) {
                    WRN("Failed to count nmethods for class: %s", meta->name);
                    return 1;
                }
                *out_nmethods = nmethods;
                return 0;
            }
        }
    }
    return 1;
}

/*
Confidence key:
50 = switch statement
45 = CMP src_regs, #...
40 = SUBS x?, src_regs, #...
20 = CMP x?, #...
10 = SUBS x?, x?, #...
5  = CBZ / CBNZ src_regs, ...
0  = nothing found / method not overridden
*/
int find_comparison(void* kernel, metaclass_t *meta, uint32_t meth_idx, uint32_t src_regs, int* out_comp_imm, int* out_conf) {
    int best_guess = -1;
    int confidence = 0;
    ssize_t stack_off = -1;

    if (meth_idx >= meta->nmethods)
        return 1;

    vtab_entry_t* meth = &meta->methods[meth_idx];
    if (!meth->overrides)
        return 1;
    uint32_t* fn = (uint32_t*)addr2ptr(kernel, meth->addr);
    uint32_t* fn_end = fn + 0x80;
    if (!fn)
        return 1;

    // find comparison, not foolproof but does the job most of the time
    for (uint32_t* insn = fn; insn < fn_end; insn++) {
        // reached another function stack frame, stop here:
        if (insn > fn && (*insn & 0b11111111111111111111111110111111) == 0b11010101000000110010001100111111) /* PACIxSP */ {
            break;
        }

        // check for moving Rn into a secondary register
        if (is_orr_reg((orr_reg_t*)insn) && src_regs & (1 << ((orr_reg_t*)insn)->Rm)) {
            src_regs |= (1 << ((orr_reg_t*)insn)->Rd);
            continue;
        }
        if (is_and((and_t*)insn) && src_regs & (1 << ((and_t*)insn)->Rn)) {
            src_regs |= (1 << ((and_t*)insn)->Rd);
            continue;
        }
        stur_t* stur = (stur_t*)insn;
        if (is_stur(stur) && (stack_off == -1) && stur->Rn == 29 && (src_regs & (1 << stur->Rt))) {
            stack_off = get_stur_off(stur);
            continue;
        }
        ldur_t* ldur = (stur_t*)insn;
        if (is_ldur(ldur) && (stack_off != -1) && ldur->Rn == 29 && get_ldur_off(ldur) == stack_off) {
            src_regs |= (1 << ldur->Rt);
            continue;
        }

        sub_imm_t* subs = (sub_imm_t*)insn;
        cbz_t* cbz = (cbz_t*)insn;
        if (is_subs_imm(subs)) {
            // this is some comparison:
            uint32_t imm = get_add_sub_imm(subs) + 1;

            // CMP + CSEL + ADRP + ADD == jumptable (aka. switch statement)
            // switches are *probably* switching on the selector
            if (subs->Rd == 31) {
                uint32_t masks[] = {
                    0b01111111111111111111111111111111, // CSEL
                    0b10011111000000000000000000000000, // ADRP
                    0b01111111100000000000000000000000, // ADD
                };
                uint32_t matches[] = {
                    0b00011010100111111001000000000000 | (subs->Rn << 5) | subs->Rn,
                    0b10010000000000000000000000000000,
                    0b00010001000000000000000000000000,
                };
                bool is_a_jumptable = true;
                for (int j = 0; j < sizeof(masks) / sizeof(uint32_t); j++) {
                    uint32_t insn2 = *(insn + 1 + j);
                    if ((insn2 & masks[j]) != matches[j]) {
                        is_a_jumptable = false;
                        break;
                    }
                }

                if (is_a_jumptable && confidence < 50) {
                    // this is a switch, very likely that we're switching on the selector
                    best_guess = imm;
                    confidence = 50;
                    continue;
                }
            }

            if (src_regs & (1 << subs->Rn)) {
                if (subs->Rd == 31) {
                    // CMP src_regs, #...
                    // this is very compelling evidence!
                    if (confidence < 45) {
                        best_guess = imm;
                        confidence = 45;
                    }
                } else if (confidence < 40) {
                    // SUBS x?, src_regs, #...
                    // pretty convincing still
                    best_guess = imm;
                    confidence = 40;
                }
                continue;
            }
            
            // not a direct compare with Rn, but in case we find nothing better, we should hold onto it
            if (subs->Rd == 31) {
                // CMP x?, #...
                if (confidence < 20) {
                    best_guess = imm;
                    confidence = 20;
                }
            } else if (confidence < 10) {
                // SUBS x?, x?, #...
                best_guess = imm;
                confidence = 10;
            }
        }
        else if (is_cbz(cbz) || is_cbnz(cbz)) {
            if (src_regs & (1 << cbz->Rt)) {
                // CBZ / CBNZ src_regs, ...
                // less compelling than a cmp
                if (confidence < 5) {
                    best_guess = 1;
                    confidence = 5;
                }
            }
        }
    }

    if (best_guess != -1) {
        // didn't find a match with Rn, but we found *something*, maybe that's good enough?
        *out_comp_imm = best_guess;
        *out_conf = confidence;
        return 0;
    }
    return 1;
}

int find_client_legacy_nmethods(void* kernel, metaclass_t* meta, int* out_nmethods, int* out_conf) {
    int comp_imm = 0;
    int ret = find_comparison(kernel, meta, g_getTargetAndMethodForIndex_idx, 1 << 2, &comp_imm, out_conf);
    if (ret == 0)
        *out_nmethods = comp_imm;
    return ret;
}

int find_client_nmethods(void* kernel, metaclass_t* meta, int* out_nmethods, int* out_conf) {
    int comp_imm = 0;
    int ret = find_comparison(kernel, meta, g_externalMethod_idx, 1 << 1, &comp_imm, out_conf);
    if (ret == 0)
        *out_nmethods = comp_imm;
    return ret;
}

int count_external_methods(void* kernel, kptr_t kbase, fixup_kind_t fixupKind, void* classes, sym_t* bsyms, size_t nsyms) {
    ARRCAST(metaclass_t, metas, classes);
    metaclass_t* IOUserClient = NULL;
    metaclass_t* IOUserClient2022 = NULL;

    // find IOUserClient and IOUserClient2022:
    for (size_t i = 0; i < metas->idx; ++i) {
        if (strcmp(metas->val[i].name, "IOUserClient") == 0) {
            if (IOUserClient) {
                ERR("Multiple candidates for %s.", metas->val[i].name);
                return 1;
            }
            IOUserClient = &metas->val[i];
        } else if (strcmp(metas->val[i].name, "IOUserClient2022") == 0) {
            if (IOUserClient2022) {
                ERR("Multiple candidates for %s.", metas->val[i].name);
                return 1;
            }
            IOUserClient2022 = &metas->val[i];
        }
    }
    if (!IOUserClient) {
        ERR("IOUserClient metaclass not found.");
        return 1;
    }
    if (!IOUserClient2022) {
        WRN("IOUserClient2022 metaclass not found.");
    }

    // find IOUserClient subclasses:
    metaclass_t** clients = malloc(metas->idx * sizeof(metaclass_t*));
    size_t clients_count = 0;
    clients[clients_count++] = IOUserClient;
    for(size_t j = 0; j < clients_count; ++j)
    {
        kptr_t addr = clients[j]->addr;
        for(size_t i = 0; i < metas->idx; ++i)
        {
            metaclass_t *meta = &metas->val[i];
            if(!meta->visited && meta->parent == addr)
            {
                clients[clients_count++] = meta;
                meta->visited = 1;
            }
        }
    }
    // unmark clients as visited:
    for (size_t i = 0; i < clients_count; ++i) {
        clients[i]->visited = 0;
    }

    // find IOUserClient2022 subclasses:
    metaclass_t** clients2022 = NULL;
    size_t clients2022_count = 0;
    if (IOUserClient2022) {
        clients2022 = malloc(clients_count * sizeof(metaclass_t*));
        clients2022[clients2022_count++] = IOUserClient2022;
        for(size_t j = 0; j < clients2022_count; ++j)
        {
            kptr_t addr = clients2022[j]->addr;
            for(size_t i = 0; i < clients_count; ++i)
            {
                metaclass_t *meta = clients[i];
                if(meta && !meta->visited && meta->parent == addr)
                {
                    clients2022[clients2022_count++] = meta;
                    meta->visited = 1;

                    // remove from clients array:
                    clients[i] = NULL;
                }
            }
        }
    }
    // unmark clients2022 as visited:
    for (size_t i = 0; i < clients2022_count; ++i) {
        clients2022[i]->visited = 0;
    }

    // patchfind method indexes:
    if (find_externalMethod_idx(kernel, IOUserClient, IOUserClient2022, &g_externalMethod_idx)) {
        ERR("Failed to find IOUserClient::externalMethod in vtable.");
        return 1;
    }
    if (find_getTargetAndMethodForIndex_idx(kernel, IOUserClient, &g_getTargetAndMethodForIndex_idx)) {
        ERR("Failed to find IOUserClient::getTargetAndMethodForIndex in vtable.");
        return 1;
    }
    if (IOUserClient2022 && find_externalMethod2_idx(kernel, IOUserClient2022, clients2022, clients2022_count, &g_externalMethod2_idx)) {
        ERR("Failed to find IOUserClient2022::externalMethod in vtable.");
        return 1;
    }
    if (IOUserClient2022 && find_dispatchExternalMethod_addr(kernel, IOUserClient2022, bsyms, nsyms, clients2022, clients2022_count, &g_dispatchExternalMethod_addr)) {
        ERR("Failed to find IOUserClient2022::dispatchExternalMethod.");
        return 1;
    }

    // try to count external methods:
    // the way we order the clients means we always handle superclasses first
    for (size_t i = 0; i < clients_count; i++) {
        int nmethods1, nmethods2, confidence1, confidence2 = 0;
        if (clients[i] && clients[i] != IOUserClient && clients[i] != IOUserClient2022) { // clients array can contain NULLs
            nmethods1 = 0; nmethods2 = 0; confidence1 = 0; confidence2 = 0;
            int ret1 = find_client_nmethods(kernel, clients[i], &nmethods1, &confidence1);
            int ret2 = find_client_legacy_nmethods(kernel, clients[i], &nmethods2, &confidence2);

            if (ret1 && ret2) {
                clients[i]->n_externalmethods = clients[i]->parentP->n_externalmethods;
            } else {
                if (confidence1 >= confidence2)
                    clients[i]->n_externalmethods = nmethods1;
                else
                    clients[i]->n_externalmethods = nmethods2;
            }
        }
    }
    for (size_t i = 0; i < clients2022_count; i++) {
        if (clients2022[i] != IOUserClient2022) {
            int ret = find_client2022_nmethods(kernel, clients2022[i], &clients2022[i]->n_externalmethods);
            if (ret) {
                clients2022[i]->n_externalmethods = clients2022[i]->parentP->n_externalmethods;
            }
        }
    }

    // cleanup:
    free(clients);
    if (clients2022)
        free(clients2022);
    return 0;
}

int do_heuristics(void* kernel, kptr_t kbase, fixup_kind_t fixupKind, void* classes, sym_t* bsyms, size_t nsyms) {
    return count_external_methods(kernel, kbase, fixupKind, classes, bsyms, nsyms);
}
