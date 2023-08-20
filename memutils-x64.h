#pragma once
#include <cstdint>
#include <optional>
#include <Windows.h>
#include <string>
#include <map>
#include <array>
#include <vector>

namespace memutils {

	// Wrapper for working with memory addresses
	class Address {
	public:
		uintptr_t ptr;

		Address(uintptr_t ptr) : ptr(ptr) {}
		Address(void* ptr) : ptr((uintptr_t)ptr) {}

		template<typename T>
		operator T() const
		{
			return (T)ptr;
		}

		Address Offset(ptrdiff_t offset) const {
			return Address(ptr + offset);
		}

		template<typename T = Address>
		T GetAbsoluteAddress(ptrdiff_t addrOffset, std::optional<uint32_t> opcodeSize = std::nullopt) const {
			return T(ptr + *(int*)(ptr + addrOffset) + opcodeSize.value_or(addrOffset + sizeof(uint32_t)));
		}

		template<typename T>
		void Set(const T& val) {
			*(T*)ptr = val;
		}

		template<typename T>
		T* As() const {
			return (T*)ptr;
		}

		template<typename T = Address>
		T Dereference() const {
			return (T)(*(uintptr_t*)ptr);
		}

	};

	// Function wrapper which can be called with arbitrary arguments
	// Made by Liberalist
	class Function {
	public:
		void* ptr;

		Function() : ptr(nullptr) {}
		Function(uintptr_t ptr) : ptr((void*)ptr) {}
		Function(void* ptr) : ptr(ptr) {}

		operator void* ()
		{
			return ptr;
		}

		template<typename ...T>
		void* __fastcall operator()(T... t) {
			return (void*)((uintptr_t(__fastcall*)(T...))ptr)(t...);
		}
		// Used to specify the return type(e. g. in case of a floating-point value)
		template<typename V, typename ...T>
		V __fastcall Call(T... t) {
			return ((V(__fastcall*)(T...))ptr)(t...);
		}

	};

	// Utility class for working with memory
	class Memory {
		// Boyer-Moore-Horspool with wildcards implementation
		static std::array<size_t, 256> FillShiftTable(const char* pattern, const uint8_t wildcard) {
			std::array<size_t, 256> bad_char_skip = {};
			size_t idx = 0;
			const size_t last = strlen(pattern) - 1;

			// Get last wildcard position
			for (idx = last; idx > 0 && (uint8_t)pattern[idx] != wildcard; --idx);
			size_t diff = last - idx;
			if (diff == 0)
				diff = 1;

			// Prepare shift table
			for (idx = 0; idx < 256; ++idx)
				bad_char_skip[idx] = diff;
			for (idx = last - diff; idx < last; ++idx)
				bad_char_skip[(uint8_t)pattern[idx]] = last - idx;
			return bad_char_skip;
		}

		static std::string ParseCombo(std::string_view combo)
		{
			const size_t patternLen = (combo.size() + 1) / 3;
			std::string pattern;
			pattern.reserve(patternLen);

			int index = 0;
			for (unsigned int i = 0; i < combo.size(); i++)
			{
				if (combo[i] == ' ')
					continue;
				else if (combo[i] == '?')
				{
					pattern += '\xCC';
					i += 1;
				}
				else
				{
					char byte = (char)strtol(&combo[i], 0, 16);
					pattern += byte;
					i += 2;
				}
			}
			return pattern;
		}

		static void* PatternScanInModule(const char* module, const char* pattern)
		{
			const auto begin = (uintptr_t)GetModuleHandleA(module);

			const auto pDosHeader = PIMAGE_DOS_HEADER(begin);
			const auto pNTHeaders = PIMAGE_NT_HEADERS((uint8_t*)(begin + pDosHeader->e_lfanew));
			const auto dwSizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;

			uint8_t* scanPos = (uint8_t*)begin;
			const uint8_t* scanEnd = (uint8_t*)(begin + dwSizeOfImage - strlen(pattern));

			const size_t last = strlen(pattern) - 1;
			const auto bad_char_skip = FillShiftTable(pattern, 0xCC);

			// Search
			for (; scanPos <= scanEnd; scanPos += bad_char_skip[scanPos[last]])
				for (size_t idx = last; idx >= 0; --idx) {
					const uint8_t elem = pattern[idx];
					if (elem != 0xCC && elem != scanPos[idx])
						break;
					if (idx == 0)
						return scanPos;
				}

			return nullptr;
		}

		using PatchSequence = std::vector<BYTE>;
		static inline std::map<uintptr_t, PatchSequence> patches;
	public:

		static void RevertPatches() {
			static auto NtProtectVirtualMemory = Memory::GetExport("ntdll.dll", "NtProtectVirtualMemory");
			for (auto& [pAddr, sequence] : patches) {
				Address addr = pAddr;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(addr, &mbi, sizeof(mbi));

				NtProtectVirtualMemory(GetCurrentProcess(), &mbi.BaseAddress, (unsigned long*)&mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
				memcpy(addr, sequence.data(), sequence.size());
				NtProtectVirtualMemory(GetCurrentProcess(), &mbi.BaseAddress, (unsigned long*)&mbi.RegionSize, mbi.Protect, &mbi.Protect);
			}
		}

		// Byte patching!
		template<size_t replSize>
		static void Patch(Address addr, BYTE const (&replacement)[replSize]) {
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(addr, &mbi, sizeof(mbi));

			// VirtualProtect is hooked by none other that Valve's gameoverlayrenderer64.dll
			// Syscalling is our option
			static auto NtProtectVirtualMemory = Memory::GetExport("ntdll.dll", "NtProtectVirtualMemory");
			NtProtectVirtualMemory(GetCurrentProcess(), &mbi.BaseAddress, (unsigned long*)&mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
			memcpy(addr, replacement, replSize);
			NtProtectVirtualMemory(GetCurrentProcess(), &mbi.BaseAddress, (unsigned long*)&mbi.RegionSize, mbi.Protect, &mbi.Protect);

			PatchSequence data;
			data.assign(replacement, replacement + replSize);
			if (!patches.contains(addr)) // not to break the reversion for dynamic patches
				patches[addr] = data;
		}


		static Address Scan(std::string_view signature, std::string_view moduleName) {
			return PatternScanInModule(moduleName.data(), ParseCombo(signature).data());
		}

		template<typename T>
		static void Copy(T* dst, T* src) {
			memcpy((void*)dst, (const void*)src, sizeof(T));
		}

		static void Copy(auto* dst, const auto* src, size_t size) {
			memcpy((void*)dst, (const void*)src, size);
		}

		// Returns an exported function, if it's available
		template<typename T = Function>
		static T GetExport(const char* dllName, const char* exportName) {
			return T(GetProcAddress(GetModuleHandleA(dllName), exportName));
		}

		// Returns a module's base address, for use with RVA
		static Address GetModule(const char* dllName) {
			return (void*)GetModuleHandleA(dllName);
		}

		template <typename T = void*>
		static T GetVM(auto obj, size_t methodIndex)
		{
			return T((*(uintptr_t**)obj)[methodIndex]);
		}

		static bool IsValidReadPtr(auto p) {
			if (!p)
				return false;
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));
			if (!VirtualQuery((void*)p, &mbi, sizeof(mbi)))
				return false;
			if (!(mbi.State & MEM_COMMIT))
				return false;
			if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
				PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
				return false;
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
				return false;
			return true;
		}

		static bool IsValidWritePtr(auto p)
		{
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));
			if (!VirtualQuery((void*)p, &mbi, sizeof(mbi)))
				return false;
			if (!(mbi.State & MEM_COMMIT))
				return false;
			if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
				return false;
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
				return false;
			return true;
		}


		static bool IsValidCodePtr(auto p)
		{
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));
			if (!VirtualQuery((void*)p, &mbi, sizeof(mbi)))
				return false;
			if (!(mbi.State & MEM_COMMIT))
				return false;
			if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
				return false;
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
				return false;
			return true;
		}
	};

	class VClass {
		virtual void dummy_fn() = 0; // so that classes have a vtable
	public:
		template<typename T>
		T& Field(int offset) const {
			return *(T*)((uintptr_t)this + offset);
		}

		template<typename T>
		T Member(int offset/*, T defaultValue = T{}*/) const {
			return *(T*)((uintptr_t)this + offset);
		}

		// Gets a pointer to a type via the offset but does not dereference it
		template<typename T>
		T* MemberInline(int offset) const {
			return (T*)((uintptr_t)this + offset);
		}

		Function GetVFunc(int index) const
		{
			return Function((*(uintptr_t**)this)[index]);
		}

		template<uint32_t index, typename RET = void*, typename ...T>
		RET CallVFunc(T... t) {
			return GetVFunc(index).Call<RET>(this, t...);
		}
	};

	// Class with no virtual methods
	class NormalClass {
	public:
		template<typename T>
		T& Field(int offset) const {
			return *(T*)((uintptr_t)this + offset);
		}

		template<typename T>
		T Member(int offset/*, T defaultValue = T{}*/) const {
			return *(T*)((uintptr_t)this + offset);
		}

		// Gets a pointer to a type via the offset but does not dereference it
		template<typename T>
		T* MemberInline(int offset) const {
			return (T*)((uintptr_t)this + offset);
		}
	};

} // namespace memutils