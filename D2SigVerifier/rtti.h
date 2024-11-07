#pragma once
#include "demangler.h"
#include <unordered_set>
#include <unordered_map>
#include <memory>

using std::shared_ptr;
using std::vector;

// Pasted from IDA's Class Informer
namespace rtti
{
	// RAII classes to not worry about allocations
	class PEImage {
		PEImage() {}
	public:
		PIMAGE_NT_HEADERS pNTHeaders;
		PIMAGE_DOS_HEADER pDosHeader;
		std::vector<char> data;

		static shared_ptr<PEImage> FromFile(std::string_view path) {
			struct SharedConstructible : PEImage {}; // What a hack!
			auto res = std::make_shared<SharedConstructible>();

			std::ifstream file(path.data(), std::ios::binary | std::ios::ate);
			std::streamsize size = file.tellg();
			file.seekg(0, std::ios::beg);

			res->data = std::vector<char>(size);
			if (file.read(res->data.data(), size))
			{
				res->pDosHeader = (PIMAGE_DOS_HEADER)res->data.data();
				res->pNTHeaders = PIMAGE_NT_HEADERS((uint8_t*)((uintptr_t)res->pDosHeader + res->pDosHeader->e_lfanew));
			}

			return res;
		}

		DWORD ToRVA(uintptr_t va) const {
			return va - pNTHeaders->OptionalHeader.ImageBase;
		}
		bool IsVA(uintptr_t addr) const {
			return addr > pNTHeaders->OptionalHeader.ImageBase && addr < pNTHeaders->OptionalHeader.ImageBase + pNTHeaders->OptionalHeader.SizeOfImage;
		}

		PIMAGE_SECTION_HEADER GetSection(std::string_view name) const {
			PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
			for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
				if ((char*)pSectionHeader->Name == name)
					return pSectionHeader;

			return nullptr;
		}

		template<typename T = uintptr_t>
		T* GetRaw(uintptr_t ptr) const {
			return (T*)((uintptr_t)data.data() + ptr);
		}

		template<typename T = uintptr_t>
		bool IsInBounds(T addr) const {
			return addr >= (uintptr_t)data.data() && addr <= (uintptr_t)data.data() + pNTHeaders->OptionalHeader.SizeOfImage;
		}
	};

	struct PEImageSection {
		PIMAGE_SECTION_HEADER pSection;
		PEImageSection(PIMAGE_SECTION_HEADER image) : pSection(image) {}
		PEImageSection() : pSection(nullptr) {}

		uintptr_t RVA2Raw(DWORD rva) const {
			return (uintptr_t)rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}

		uintptr_t Raw2RVA(DWORD ptr) const {
			return (uintptr_t)ptr - pSection->PointerToRawData + pSection->VirtualAddress;
		}

		bool IsInSection(DWORD rva) const {
			return rva >= pSection->VirtualAddress && rva < pSection->VirtualAddress + pSection->Misc.VirtualSize;
		}
	};

	class RTTI {
		shared_ptr<PEImage> loadedImage;
		// We need 3 sections in total to parse RTTI:
		// .rdata: Complete Object Locators and VMTs 
		// .data: Type Info
		// .text: Methods
		struct PESections {
			PEImageSection rdata, data, text;
		} sections;

		bool IsValidAddress(auto t) const {
			return t >= (void*)((uintptr_t)loadedImage->data.data()) && t <= (void*)((uintptr_t)loadedImage->data.data() + loadedImage->pNTHeaders->OptionalHeader.SizeOfImage);
		}

		using rva_t = uint32_t;

		struct type_info
		{
			uintptr_t vfptr;	       // type_info class vftable
			uintptr_t _M_data;      // NULL until loaded at runtime
			char _M_d_name[32]; // Mangled name (prefix: .?AV=classes, .?AU=structs)
		};

		struct _RTTIBaseClassDescriptor
		{
			UINT typeDescriptor;        // 00 Type descriptor of the class  *X64 int32 offset
			UINT numContainedBases;		// 04 Number of nested classes following in the Base Class Array
			struct PMD
			{
				int mdisp;	// 00 Member displacement
				int pdisp;  // 04 Vftable displacement
				int vdisp;  // 08 Displacement inside vftable
			} pmd;					// 08 Pointer-to-member displacement info
			UINT attributes;			// 14 Flags
		};

		struct _RTTIClassHierarchyDescriptor
		{
			constexpr static inline uint32_t SIGNATURE = 0;

			uint32_t signature;			// 00 Zero until loaded
			uint32_t attributes;		// 04 Flags
			uint32_t numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
			rva_t	 baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*
		};

		struct _RTTICompleteObjectLocator
		{
			constexpr static inline uint32_t SIGNATURE = 1;

			uint32_t signature;				// 00 32bit zero, 64bit one, until loaded
			uint32_t offset;				// 04 Offset of this vftable in the complete class
			uint32_t cdOffset;				// 08 Constructor displacement offset

			rva_t typeDescriptor,	    // 0C (type_info *) of the complete class  *X64 int32 offset
				classDescriptor,       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy  *X64 int32 offset
				objectBase;            // 14 Object base offset (base = ptr col - objectBase)
		};

	public:
		RTTI(const shared_ptr<PEImage>& image) : loadedImage(image) {
			sections = {
				loadedImage->GetSection(".rdata"),
				loadedImage->GetSection(".data"),
				loadedImage->GetSection(".text")
			};
		}

		struct VMTInfo {
			uintptr_t addr{};
			std::string_view name;
			uint32_t methodCount{};

			//VMTInfo() {}
			//VMTInfo(VMTInfo&& o) noexcept : name(std::move(o.name)), addr(o.addr), methodCount(o.methodCount) {}
			//VMTInfo& operator=(VMTInfo&& o) noexcept {
			//	name = move(o.name);
			//	addr = o.addr;
			//	methodCount = o.methodCount;
			//	return *this;
			//}
		};

		void CalculateMethodCount(VMTInfo& vmt) {
			vmt.methodCount = 0;
			for (auto i = (uintptr_t*)vmt.addr; ; i++) {
				auto addr = loadedImage->ToRVA(*i);
				if (!loadedImage->IsVA(*i) || !sections.text.IsInSection(addr))
					break;

				vmt.methodCount++;
			}
		}

		int32_t GetIndexOfMethod(const VMTInfo& vmt, uintptr_t ptr) const {
			auto rva = sections.text.Raw2RVA(ptr - (uintptr_t)loadedImage->pDosHeader);
			for (auto i = (uintptr_t*)vmt.addr; i < (uintptr_t*)vmt.addr + vmt.methodCount; i++) {
				if (loadedImage->ToRVA(*i) == rva)
					return (int32_t)((uintptr_t)i - vmt.addr) / sizeof(void*);
			}
			return -1;
		}

		// Testing typeinfo's validity involves checking its demangled name, so we
		// save time and resources on that by directly obtaining the name
		const char* GetTypeInfoClassName(type_info* ti) {
			if (!ti->vfptr) return nullptr;

			if (ti->_M_d_name[0] != '.') return nullptr;

			return UnDN::Demangle(ti->_M_d_name + 1);
		}

		bool IsValid(const _RTTIBaseClassDescriptor* bc, uintptr_t colBase64 = NULL) const {
			// Valid flags are the lower byte only
			if ((bc->attributes & 0xFFFFFF00) != 0)
				return false;

			// Check for valid type_info
			type_info* typeInfo = (type_info*)((uintptr_t)loadedImage->pDosHeader + sections.data.RVA2Raw(bc->typeDescriptor));
			return IsValidAddress(typeInfo);
		};

		bool IsValid(const _RTTIClassHierarchyDescriptor* ch, uintptr_t colBase64 = NULL) const {
			if (ch->signature != 0)
				return false;

			if ((ch->attributes & 0xFFFFFFF0) != 0)
				return false;

			if (ch->numBaseClasses < 1)
				return false;

			auto baseClassArray = (uint32_t*)(colBase64 + (UINT64)ch->baseClassArray);

			auto baseClassDescriptor = (_RTTIBaseClassDescriptor*)(colBase64 + (UINT64)*baseClassArray);
			return IsValidAddress(baseClassDescriptor) && IsValid(baseClassDescriptor, colBase64);


			return false;
		};

		bool IsValid(const _RTTICompleteObjectLocator* col) const {
			if (col->signature != 1)
				return false;

			if (
				col->objectBase == 0
				|| col->typeDescriptor == 0
				|| col->classDescriptor == 0
				)
				return false;

			uint64_t colBase = (uintptr_t)col - col->objectBase;

			type_info* typeInfo = loadedImage->GetRaw<type_info>(sections.data.RVA2Raw(col->typeDescriptor));
			if (!IsValidAddress(typeInfo))
				return false;

			auto classDescriptor =
				(_RTTIClassHierarchyDescriptor*)(colBase + (uintptr_t)col->classDescriptor);
			return IsValidAddress(classDescriptor) && IsValid(classDescriptor, colBase);
		}

		type_info* GetTypeDescriptor(const _RTTICompleteObjectLocator* col) const {
			return loadedImage->GetRaw<type_info>(sections.data.RVA2Raw(col->typeDescriptor));
		}

		std::unordered_map<std::string_view, VMTInfo> FindVMTs() {
			std::unordered_map<std::string_view, VMTInfo> res;

			auto begin = loadedImage->GetRaw<uintptr_t>(sections.rdata.pSection->PointerToRawData);
			auto end = (uintptr_t*)((uintptr_t)begin + sections.rdata.pSection->SizeOfRawData);

			for (auto i = begin; i < end; i++) {
				auto addr = *i;
				if (loadedImage->IsVA(addr) && sections.rdata.IsInSection(loadedImage->ToRVA(addr))) {
					auto col = loadedImage->GetRaw<_RTTICompleteObjectLocator>(sections.rdata.RVA2Raw(loadedImage->ToRVA(addr)));

					if (!IsValid(col))
						continue;

					type_info* typeInfo = loadedImage->GetRaw<type_info>(sections.data.RVA2Raw(col->typeDescriptor));

					VMTInfo inf;

					auto name = GetTypeInfoClassName(typeInfo);
					if (!name)
						continue;

					inf.addr = (uintptr_t)(i + 1);
					inf.name = name;

					CalculateMethodCount(inf);

					if (!col->offset) {
						res[name] = inf;
					}

					i += inf.methodCount;
				}
			}
			return res;
		}
	};
}

std::ostream& operator<<(std::ostream& out, const rtti::RTTI::VMTInfo& x) {
	return (out << "VMT at " << std::hex << x.addr << ": " << x.name << "(" << std::dec << x.methodCount << " methods)");
}