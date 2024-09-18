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
		vector<char> data;

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

		DWORD RvaToRawAddress(DWORD rva)  const {
			PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
			for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
				DWORD sectionVA = pSectionHeader->VirtualAddress;
				DWORD sectionSize = pSectionHeader->Misc.VirtualSize;
				if (rva >= sectionVA && rva < sectionVA + sectionSize)
					return (rva - sectionVA) + pSectionHeader->PointerToRawData;
			}
			return 0;
		}

		PIMAGE_SECTION_HEADER GetSection(std::string_view name) const {
			PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
			for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
				if ((char*)pSectionHeader->Name == name) {
					DWORD sectionVA = pSectionHeader->VirtualAddress;
					DWORD sectionSize = pSectionHeader->Misc.VirtualSize;
					return pSectionHeader;
				}
			}
			return 0;
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
			return rva >= pSection->VirtualAddress && rva <= pSection->VirtualAddress + pSection->Misc.VirtualSize;
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

		bool bounded(auto t) const {
			return t >= (void*)((uintptr_t)loadedImage->data.data()) && t <= (void*)((uintptr_t)loadedImage->data.data() + loadedImage->pNTHeaders->OptionalHeader.SizeOfImage);
		}

		using rva_t = uint32_t;

	public:
		struct VMTInfo {
			uintptr_t addr{};
			std::string name;
			uint32_t methodCount{};
			
			VMTInfo() {}
			VMTInfo(VMTInfo&& o) noexcept : name(std::move(o.name)), addr(o.addr), methodCount(o.addr) {}
			VMTInfo& operator=(VMTInfo&& o) noexcept {
				name = move(o.name);
				addr = o.addr;
				methodCount = o.addr;
				return *this;
			}

			void CalculateMethodCount(const RTTI& rtti) {
				methodCount = 0;
				for (auto i = (uintptr_t*)addr; ; i++) {
					auto addr = rtti.loadedImage->ToRVA(*i);
					if (!rtti.loadedImage->IsVA(*i) || !rtti.sections.text.IsInSection(addr))
						break;

					methodCount++;
				}
			}

			int32_t GetIndexOfMethod(const RTTI& rtti, uintptr_t ptr) const {
				auto rva = rtti.sections.text.Raw2RVA(ptr - (uintptr_t)rtti.loadedImage->pDosHeader);
				for (auto i = (uintptr_t*)addr; i < (uintptr_t*)addr + methodCount; i++) {
					if (rtti.loadedImage->ToRVA(*i) == rva)
						return (int32_t)((uintptr_t)i - addr) / 8;
				}
				return -1;
			}
		};


		struct type_info
		{
			uintptr_t vfptr;	       // type_info class vftable
			uintptr_t _M_data;      // NULL until loaded at runtime
			char _M_d_name[32]; // Mangled name (prefix: .?AV=classes, .?AU=structs)

			std::string_view GetDemangledName() const {
				return UnDN::Demangle(_M_d_name + 1);
			}

			bool isNameValid() const
			{
				// Should start with a period
				if (_M_d_name[0] != '.')
					return false;

				using namespace UnDN;

				if (LPSTR s = __unDName(NULL, _M_d_name + 1, 0, (UnDN::_Alloc)malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU)))
				{
					free(s);
					return true;
				}

				return false;
			}

			bool isValid() const {
				return vfptr && _M_data == 0 && isNameValid();
			};
		};
		struct PMD
		{
			int mdisp;	// 00 Member displacement
			int pdisp;  // 04 Vftable displacement
			int vdisp;  // 08 Displacement inside vftable
		};

		struct _RTTIBaseClassDescriptor
		{
			UINT typeDescriptor;        // 00 Type descriptor of the class  *X64 int32 offset
			UINT numContainedBases;		// 04 Number of nested classes following in the Base Class Array
			PMD pmd;					// 08 Pointer-to-member displacement info
			UINT attributes;			// 14 Flags

			bool isValid(const RTTI& rtti, uintptr_t colBase64 = NULL) const {
				// Valid flags are the lower byte only
				if ((attributes & 0xFFFFFF00) != 0)
					return false;

				// Check for valid type_info
				type_info* typeInfo = (type_info*)((uintptr_t)rtti.loadedImage->pDosHeader + rtti.sections.data.RVA2Raw(typeDescriptor));
				return rtti.bounded(typeInfo) && typeInfo->isValid();
			};
		};

		struct _RTTIClassHierarchyDescriptor
		{
			constexpr static inline uint32_t SIGNATURE = 0;

			uint32_t signature;			// 00 Zero until loaded
			uint32_t attributes;		// 04 Flags
			uint32_t numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
			rva_t	 baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*

			bool isValid(const RTTI& rtti, uintptr_t colBase64 = NULL) const {
				if (signature != 0)
					return false;

				if ((attributes & 0xFFFFFFF0) != 0)
					return false;

				if (numBaseClasses >= 1)
				{
					auto baseClassArray = (uint32_t*)(colBase64 + (UINT64)this->baseClassArray);

					auto baseClassDescriptor = (_RTTIBaseClassDescriptor*)(colBase64 + (UINT64)*baseClassArray);
					return rtti.bounded(baseClassDescriptor) && baseClassDescriptor->isValid(rtti, colBase64);
				}

				return false;
			};
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

			type_info* GetTypeDescriptor(const RTTI& rtti) const {
				return rtti.loadedImage->GetRaw<type_info>(rtti.sections.data.RVA2Raw(typeDescriptor));
			}

			bool isValid(const RTTI& rtti) const {
				// Check signature
				if (signature != 1)
					return false;

				if (objectBase != 0 &&
					typeDescriptor != 0 &&
					classDescriptor != 0)
				{
					uint64_t colBase = (uintptr_t)this - this->objectBase;

					type_info* typeInfo = rtti.loadedImage->GetRaw<type_info>(rtti.sections.data.RVA2Raw(typeDescriptor));
					if (!rtti.bounded(typeInfo) ||
						!typeInfo->isValid())
						return false;

					auto classDescriptor =
						(_RTTIClassHierarchyDescriptor*)(colBase + (uintptr_t)this->classDescriptor);
					return rtti.bounded(classDescriptor) && classDescriptor->isValid(rtti, colBase);
				}

				return false;
			}
		};

		RTTI(const shared_ptr<PEImage>& image) : loadedImage(image) {
			sections = {
				loadedImage->GetSection(".rdata"),
				loadedImage->GetSection(".data"),
				loadedImage->GetSection(".text")
			};
		}

		VMTInfo FindVMT(const PEImage& image, std::string_view name) {

			auto begin = loadedImage->GetRaw<uintptr_t>(sections.rdata.pSection->PointerToRawData);
			auto end = (uintptr_t*)((uintptr_t)begin + sections.rdata.pSection->SizeOfRawData);

			VMTInfo inf;
			for (auto i = begin; i < end; i++) {
				auto addr = *i;
				if (loadedImage->IsVA(addr) && sections.rdata.IsInSection(loadedImage->ToRVA(addr))) {
					auto col = loadedImage->GetRaw<_RTTICompleteObjectLocator>(sections.rdata.RVA2Raw(loadedImage->ToRVA(addr)));

					if (!col->isValid(*this))
						continue;

					auto vmtName = col->GetTypeDescriptor(*this)->GetDemangledName();
					inf.addr = (uintptr_t)(i + 1);
					inf.name = vmtName;
					inf.CalculateMethodCount(*this);

					i += inf.methodCount;

					//if (vmtName != name) {
					//	free((void*)vmtName.data());
					//	continue;
					//}

					return inf;
				}
			}
			return {};
		}

		std::unordered_map<std::string_view, VMTInfo> FindVMTs() {
			std::unordered_map<std::string_view, VMTInfo> res;

			auto begin = loadedImage->GetRaw<uintptr_t>(sections.rdata.pSection->PointerToRawData);
			auto end = (uintptr_t*)((uintptr_t)begin + sections.rdata.pSection->SizeOfRawData);

			for (auto i = begin; i < end; i++) {
				auto addr = *i;
				if (loadedImage->IsVA(addr) && sections.rdata.IsInSection(loadedImage->ToRVA(addr))) {
					auto col = loadedImage->GetRaw<_RTTICompleteObjectLocator>(sections.rdata.RVA2Raw(loadedImage->ToRVA(addr)));

					if (!col->isValid(*this))
						continue;

					VMTInfo inf;

					auto name = col->GetTypeDescriptor(*this)->GetDemangledName();
					name = name.substr(name.find(' ') + 1);
					inf.addr = (uintptr_t)(i + 1);
					inf.name = name;
					inf.CalculateMethodCount(*this);

					if (!col->offset)
						res[name] = std::move(inf);

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