#pragma once
#include "demangler.h"
#include <unordered_set>
#include <unordered_map>

// Pasted from IDA's Class Informer
namespace rtti
{
	// RAII classes to not worry about allocations
	class PEImage {
	public:
		PIMAGE_NT_HEADERS pNTHeaders;
		LPVOID lpFileBase;
		HANDLE hFile;
		HANDLE hFileMapping;
		PIMAGE_DOS_HEADER pDosHeader;

		PEImage() {}

		void Destroy() {
			UnmapViewOfFile(lpFileBase);
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
		}

		static PEImage FromFile(std::string_view path) {
			PEImage res;
			res.hFile = CreateFileA(path.data(), GENERIC_READ, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

			if (res.hFile == INVALID_HANDLE_VALUE)
			{
				printf("Couldn't open file with CreateFile()\n");
				return res;
			}

			res.hFileMapping = CreateFileMapping(res.hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (res.hFileMapping == 0)
			{
				CloseHandle(res.hFile);
				printf("Couldn't open file mapping with CreateFileMapping()\n");
				return res;
			}

			res.lpFileBase = MapViewOfFile(res.hFileMapping, FILE_MAP_READ, 0, 0, 0);
			if (res.lpFileBase == 0)
			{
				CloseHandle(res.hFileMapping);
				CloseHandle(res.hFile);
				printf("Couldn't map view of file with MapViewOfFile()\n");
				return res;
			}
			res.pDosHeader = (PIMAGE_DOS_HEADER)res.lpFileBase;
			res.pNTHeaders = PIMAGE_NT_HEADERS((uint8_t*)((uintptr_t)res.pDosHeader + res.pDosHeader->e_lfanew));
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
			return (T*)((uintptr_t)lpFileBase + ptr);
		}

		template<typename T = uintptr_t>
		bool IsInBounds(T addr) const {
			return addr >= (uintptr_t)lpFileBase && addr <= (uintptr_t)lpFileBase + pNTHeaders->OptionalHeader.SizeOfImage;
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
		inline static PEImage loadedImage;

		// We need 3 sections in total to parse RTTI:
		// .rdata: Complete Object Locators and VMTs 
		// .data: Type Info
		// .text: Methods
		enum Sections {
			RDATA,
			DATA,
			TEXT
		};

		inline static PEImageSection sections[3];

		template<typename T>
		static bool IsInBounds(T val, std::pair<T, T> bounds) {
			return val >= bounds.first && val <= bounds.second;
		}

		static bool bounded(auto t) {
			//return IsInBounds((uintptr_t)t - (uintptr_t)lpFileBase + rdataSec->PointerToRawData, rdataBounds);
			return t >= (void*)((uintptr_t)loadedImage.lpFileBase) && t <= (void*)((uintptr_t)loadedImage.lpFileBase + loadedImage.pNTHeaders->OptionalHeader.SizeOfImage);
		}

		using rva_t = uint32_t;

	public:
		struct VMTInfo {
			uintptr_t addr{};
			std::string_view name;
			uint32_t methodCount{};

			void CalculateMethodCount() {
				methodCount = 0;
				for (auto i = (uintptr_t*)addr; ; i++) {
					auto addr = loadedImage.ToRVA(*i);
					if (!loadedImage.IsVA(*i) || !sections[TEXT].IsInSection(addr))
						break;

					methodCount++;
				}
			}

			int32_t GetIndexOfMethod(uintptr_t ptr) const {
				auto rva = sections[TEXT].Raw2RVA(ptr - (uintptr_t)loadedImage.lpFileBase);
				for (auto i = (uintptr_t*)addr; i < (uintptr_t*)addr + methodCount; i++) {
					if (loadedImage.ToRVA(*i) == rva)
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

				if (LPSTR s = __unDName(NULL, _M_d_name + 1, 0, mallocWrap, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY)))
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

			bool isValid(uintptr_t colBase64 = NULL) const {
				// Valid flags are the lower byte only
				if ((attributes & 0xFFFFFF00) != 0)
					return false;

				// Check for valid type_info
				type_info* typeInfo = (type_info*)((uintptr_t)loadedImage.lpFileBase + sections[DATA].RVA2Raw(typeDescriptor));
				return bounded(typeInfo) && typeInfo->isValid();
			};
		};

		struct _RTTIClassHierarchyDescriptor
		{
			constexpr static inline uint32_t SIGNATURE = 0;

			uint32_t signature;			// 00 Zero until loaded
			uint32_t attributes;		// 04 Flags
			uint32_t numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
			rva_t	 baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*

			bool isValid(uintptr_t colBase64 = NULL) const {
				if (signature != 0)
					return false;

				if ((attributes & 0xFFFFFFF0) != 0)
					return false;

				if (numBaseClasses >= 1)
				{
					auto baseClassArray = (uint32_t*)(colBase64 + (UINT64)this->baseClassArray);

					auto baseClassDescriptor = (_RTTIBaseClassDescriptor*)(colBase64 + (UINT64)*baseClassArray);
					return bounded(baseClassDescriptor) && baseClassDescriptor->isValid(colBase64);
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

			type_info* GetTypeDescriptor() const {
				return loadedImage.GetRaw<type_info>(sections[DATA].RVA2Raw(typeDescriptor));
			}

			bool isValid() const {
				// Check signature
				if (signature != 1)
					return false;

				if (objectBase != 0 &&
					typeDescriptor != 0 &&
					classDescriptor != 0)
				{
					uint64_t colBase = (uintptr_t)this - this->objectBase;

					type_info* typeInfo = loadedImage.GetRaw<type_info>(sections[DATA].RVA2Raw(typeDescriptor));
					if (!bounded(typeInfo) ||
						!typeInfo->isValid())
						return false;

					auto classDescriptor =
						(_RTTIClassHierarchyDescriptor*)(colBase + (uintptr_t)this->classDescriptor);
					return bounded(classDescriptor) && classDescriptor->isValid(colBase);
				}

				return false;
			}
		};

		static VMTInfo FindVMT(const PEImage& image, std::string_view name) {
			loadedImage = image;

			sections[RDATA] = loadedImage.GetSection(".rdata");
			sections[DATA] = loadedImage.GetSection(".data");
			sections[TEXT] = loadedImage.GetSection(".text");

			auto begin = loadedImage.GetRaw<uintptr_t>(sections[RDATA].pSection->PointerToRawData);
			auto end = (uintptr_t*)((uintptr_t)begin + sections[RDATA].pSection->SizeOfRawData);

			VMTInfo inf;
			for (auto i = begin; i < end; i++) {
				auto addr = *i;
				if (loadedImage.IsVA(addr) && sections[RDATA].IsInSection(loadedImage.ToRVA(addr))) {
					auto col = loadedImage.GetRaw<_RTTICompleteObjectLocator>(sections[RDATA].RVA2Raw(loadedImage.ToRVA(addr)));

					if (!col->isValid())
						continue;

					auto vmtName = col->GetTypeDescriptor()->GetDemangledName();
					auto prefixless = vmtName.substr(vmtName.find(' ') + 1);
					inf.addr = (uintptr_t)(i + 1);
					inf.name = prefixless;
					inf.CalculateMethodCount();

					i += inf.methodCount;

					if (prefixless != name) {
						free((void*)vmtName.data());
						continue;
					}

					return inf;
				}
			}
			return {};
		}

		static std::unordered_map<std::string_view, VMTInfo> _FindVMTs(const PEImage& image) {
			std::unordered_map<std::string_view, VMTInfo> res;

			loadedImage = image;

			sections[RDATA] = loadedImage.GetSection(".rdata");
			sections[DATA] = loadedImage.GetSection(".data");
			sections[TEXT] = loadedImage.GetSection(".text");

			auto begin = loadedImage.GetRaw<uintptr_t>(sections[RDATA].pSection->PointerToRawData);
			auto end = (uintptr_t*)((uintptr_t)begin + sections[RDATA].pSection->SizeOfRawData);

			for (auto i = begin; i < end; i++) {
				auto addr = *i;
				if (loadedImage.IsVA(addr) && sections[RDATA].IsInSection(loadedImage.ToRVA(addr))) {
					auto col = loadedImage.GetRaw<_RTTICompleteObjectLocator>(sections[RDATA].RVA2Raw(loadedImage.ToRVA(addr)));

					if (!col->isValid())
						continue;

					VMTInfo inf;

					auto name = col->GetTypeDescriptor()->GetDemangledName();
					name = name.substr(name.find(' ') + 1);
					inf.addr = (uintptr_t)(i + 1);
					inf.name = name;
					inf.CalculateMethodCount();

					if (!col->offset)
						res[name] = inf;

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