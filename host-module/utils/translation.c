#include "translation.h"
#include <linux/pgtable.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <linux/sev.h>

u64 set_mapping(u64 host_cr3, u64 va, u64 pfn){
		u64 p4d_offset = (va >> 39) & 0x1ff;
		u64 pmd_offset = (va >> 30) & 0x1ff;
		u64 pgd_offset = (va >> 21) & 0x1ff;
  		u64 pte_offset = (va >> 12) & 0x1ff;
		u64 entry;
		u64 *entry_va;
    	entry_va = (u64*)__va((void *)(host_cr3 + p4d_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pmd_offset * 8);
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pgd_offset * 8);
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pte_offset * 8);
		entry = *entry_va;
    	*entry_va = (entry & 0xfff) | (pfn) | (1ULL << 51) | 1ULL;
		return 0;
}

u64 gpa2spa(u64 guest_cr3, u64 va){
		va &= HOST_PHYSICAL_ADRS_MASK;
		u64 p4d_offset = (va >> 39) & 0x1ff;
		u64 pgd_offset = (va >> 30) & 0x1ff;
		u64 pmd_offset = (va >> 21) & 0x1ff;
    	u64 pte_offset = (va >> 12) & 0x1ff;
    	u64 page_offset = (va) & 0xfff;
		u64 *entry_va;
		u64 entry;
    	entry_va = (u64*)__va(guest_cr3 + p4d_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pgd_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pmd_offset * 8);
   		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}
    	entry_va = (u64*)__va(entry + pte_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}
    	return entry + page_offset;
}


u64 gpa2sva_set_mapping(u64 guest_cr3, u64 va){
		va &= HOST_PHYSICAL_ADRS_MASK;
		u64 p4d_offset = (va >> 39) & 0x1ff;
		u64 pgd_offset = (va >> 30) & 0x1ff;
		u64 pmd_offset = (va >> 21) & 0x1ff;
    	u64 pte_offset = (va >> 12) & 0x1ff;
    	u64 page_offset = (va) & 0xfff;
		u64 *entry_va;
		u64 entry;
    	entry_va = (u64*)__va(guest_cr3 + p4d_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pgd_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pmd_offset * 8);
   		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}
    	entry_va = (u64*)__va(entry + pte_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

		u64 host_cr3;
		asm volatile ("mov %%cr3, %0" : "=r" (host_cr3));
		set_mapping(host_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK, (u64)__va(entry + page_offset), entry);
    	return (u64)__va(entry + page_offset);
}

u64 gpa2sva(u64 guest_cr3, u64 va){
		guest_cr3 = guest_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
		va &= HOST_PHYSICAL_ADRS_MASK;
		u64 p4d_offset  = (va >> 39) & 0x1ff;
		u64 pgd_offset  = (va >> 30) & 0x1ff;
		u64 pmd_offset  = (va >> 21) & 0x1ff;
    	u64 pte_offset  = (va >> 12) & 0x1ff;
    	u64 page_offset  = (va) & 0xfff;
		u64 *entry_va;
		u64 entry;
    	entry_va = (u64*)__va(guest_cr3 + p4d_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pgd_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pmd_offset * 8);
   		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	entry_va = (u64*)__va(entry + pte_offset * 8);
    	entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    	if(entry == 0){
			return -1;
    	}

    	return (u64)__va(entry + page_offset);
}

u64 set_c(u64 host_cr3, u64 va){
		host_cr3 = host_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
		u64 p4d_offset = (va >> 39) & 0x1ff;
		u64 pmd_offset = (va >> 30) & 0x1ff;
		u64 pgd_offset = (va >> 21) & 0x1ff;
    	u64 pte_offset = (va >> 12) & 0x1ff;
    	u64 page_offset = (va) & 0xfff;
		u64 entry;
		u64 *entry_va;
    	entry_va = (u64*)__va((void *)(host_cr3 + p4d_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pmd_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pgd_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pte_offset * 8));
		entry = *entry_va;
		*entry_va = entry & (~(1ULL << 4));
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    
		return (u64)__va(entry + page_offset);
}

u64 set_uc(u64 host_cr3, u64 va){
		host_cr3 = host_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
		u64 p4d_offset = (va >> 39) & 0x1ff;
		u64 pmd_offset = (va >> 30) & 0x1ff;
		u64 pgd_offset = (va >> 21) & 0x1ff;
    	u64 pte_offset = (va >> 12) & 0x1ff;
    	u64 page_offset = (va) & 0xfff;
		u64 entry;
		u64 *entry_va;
    	entry_va = (u64*)__va((void *)(host_cr3 + p4d_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pmd_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pgd_offset * 8));
		entry = *entry_va;
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    	entry_va = (u64*)__va((void *)(entry + pte_offset * 8));
		entry = *entry_va;
		*entry_va = entry | (1ULL << 4);
		entry = entry & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    
		return (u64)__va(entry + page_offset);
}

