#include "pch.h"
#include <fstream>
#include <iostream>

#include <Windows.h>
#include <cstdint>

#include <string>
#include <unordered_map>
#include <span>
#include <format>
#include <chrono>
#include <array>
#include <set>
#include <assert.h>
#include <filesystem>

#include "memutils-x64.h"

#include <ShlObj_core.h>
#include "schema.h"
#include <TlHelp32.h>
#include <thread>

using namespace memutils;

class ClassDescription;

int scopeCount = 0;
int scopesDumped = 0;

class CSchemaSystemTypeScope : public VClass {
public:
	CSchemaClassInfo* FindDeclaredClass(const char* class_name) {
		CSchemaClassInfo* class_info;

		CallVFunc<2>(&class_info, class_name);
		return class_info;
	}

	std::string_view GetScopeName() {
		return { m_name_.data() };
	}

	//CUtlTSHash<CSchemaClassBinding*> GetClasses() {
	//	return Member< CUtlTSHash<CSchemaClassBinding*> >(0x588);
	//}

	std::array<char, 256> m_name_ = {};
};


struct SchemaParentInfo {
	uintptr_t idk;
	ClassDescription* parent;
};

struct SchemaTypeDescription {
	uintptr_t idk;
	const char* name;
	uintptr_t idk2;
};


struct ClassDescription {
	ClassDescription* self;        //0
	const char* className;         //8
	const char* modulename;        //10
	uint32_t classSize;               //18
	short membersSize;		   //1c
	char pad[6];				   //20
	SchemaClassFieldData_t* membersDescription; //28
	uintptr_t idk2;                //30
	SchemaParentInfo* parentInfo;  //38
};



struct less_than_key
{
	inline bool operator() (const SchemaClassFieldData_t& struct1, const SchemaClassFieldData_t& struct2) const
	{
		return (struct1.m_single_inheritance_offset < struct2.m_single_inheritance_offset);
	}
};

std::unordered_map<std::string, std::set<SchemaClassFieldData_t, less_than_key>> Netvars;

typedef void* (*oCreateInterface)(const char*, int);
oCreateInterface pCreateInterface;
uintptr_t CreateInterface(const char* szModule, const char* szInterface) {
	pCreateInterface = (oCreateInterface)GetProcAddress(GetModuleHandleA(szModule), "CreateInterface");
	return (uintptr_t)pCreateInterface(szInterface, 0);
}

class CSchemaSystem : public VClass {
public:
	CSchemaSystemTypeScope* GlobalTypeScope(void) {
		return CallVFunc<11, CSchemaSystemTypeScope*>();
	}

	CSchemaSystemTypeScope* FindTypeScopeForModule(const char* m_module_name) {
		return CallVFunc<13, CSchemaSystemTypeScope*>(m_module_name);
	}

	CUtlVector<CSchemaSystemTypeScope*> GetTypeScopes() {
		return Member<CUtlVector<CSchemaSystemTypeScope*>>(0x188);
	}
};

CSchemaSystem* SchemaSystem = 0;

inline void DumpClassMembers(CSchemaClassInfo* classDesc) {
	std::string className = classDesc->m_name;

	if (Netvars.count(className))
		return;

	std::cout << "Dumping " << className << "...\n";

	for (const auto& desc : classDesc->GetFields()) {
		Netvars[className].insert(desc);
		//		std::cout << std::format("{}: {} ({})\n", info.schematypeptr->name, info.name, info.offset);
	}

	if (classDesc->GetBaseClass())
		DumpClassMembers(*classDesc->GetBaseClass());
}

template<typename... Args>
void SchemaDumpToMap(const char* _module, Args&&... args) {
	const char* classes[sizeof...(args)] = { std::forward<Args>(args)... };
	auto typeScope = SchemaSystem->CallVFunc<13, CSchemaSystemTypeScope*>(_module, nullptr); // second arg is a buffer for something

	if (!typeScope)
		return;

	for (auto& _class : classes) {
		//std::cout << "Scope " << std::hex << Scope << std::dec << std::endl;
		auto classDesc = typeScope->FindDeclaredClass(_class);
		if (!classDesc) {
			std::cout << "No such class: " << _class << "\n";
			return;
		}
		DumpClassMembers(classDesc);
	}
}

std::string getTimeStr() {
	std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	std::string s(30, '\0');
	std::strftime(&s[0], s.size(), "%d-%m-%Y %H:%M:%S", std::localtime(&now));
	return s;
}

void DumpClassToText(const CSchemaClassInfo* classDesc, std::ofstream& fout, std::set<std::string>& parents) {
	fout << std::hex;

	auto parentInfo = classDesc->GetBaseClass().value_or(nullptr);
	while (parentInfo) {
		if (!parents.contains(parentInfo->m_name)) {
			parents.insert(parentInfo->m_name);
			DumpClassToText(parentInfo, fout, parents);
		}
		parentInfo = parentInfo->GetBaseClass().value_or(nullptr);
	}

	fout << "Size: 0x" << std::hex << classDesc->m_size << "\n";
	fout << classDesc->m_name;

	if (classDesc->GetBaseClass())
		fout << " : " << (*classDesc->GetBaseClass())->m_name;
	fout << '\n';

	if (classDesc->m_fields_size == 0)
		fout << "<no members>\n";
	else
		for (uintptr_t i = 0; i < classDesc->m_fields_size; i++) {
			SchemaClassFieldData_t field = classDesc->m_fields[i];
			fout << std::format("\t{} {} {:#x};\n", field.m_type->m_name_, field.m_name, field.m_single_inheritance_offset);
		}
	fout << '\n';
}

struct InterfaceInfo {
	void(*CreateInterface)();
	const char* m_szName;
	InterfaceInfo* m_pNext;
};

void DumpAllClasses(const std::string& dir) {
	auto scopes = SchemaSystem->GetTypeScopes();
	scopeCount = scopes.m_Size;

	//for (auto scope : scopes) {
	//	std::thread([&, scope]() {

	//		auto classes = scope->GetClasses();
	//		std::filesystem::create_directory(dir + "\\" + scope->GetScopeName().data());

	//		for (const auto _class : classes.GetElements()) {
	//			std::ofstream fout(dir + "\\" + scope->GetScopeName().data() + "\\" + _class->m_name + ".txt");

	//			const auto classDesc = scope->FindDeclaredClass(_class->m_name);
	//			std::set<std::string> parents;
	//			DumpClassToText(classDesc, fout, parents);

	//			fout.close();
	//		}
	//		++scopesDumped;
	//		}).detach();
	//}
}

void SaveInterfacesToFile(std::ofstream& fout) {
	using namespace std;

	set<std::string> modules;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	MODULEENTRY32 modEntry{ 0 };
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		modEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &modEntry))
		{
			do
			{
				if (GetProcAddress(modEntry.hModule, "CreateInterface"))
					modules.insert(modEntry.szModule);

			} while (Module32Next(hSnapshot, &modEntry));
		}
		CloseHandle(hSnapshot);
	}

	set<string> interfaceNames;
	for (auto dll : modules) {
		auto interfacePointer = Memory::GetExport<Address>(dll.c_str(), "CreateInterface").GetAbsoluteAddress<InterfaceInfo**>(3);
		if (!Memory::IsValidReadPtr(interfacePointer))
			continue;

		fout << dll << ": \n";
		auto pInterface = *interfacePointer;
		while (pInterface) {
			if (pInterface->m_szName)
				interfaceNames.insert(pInterface->m_szName);

			pInterface = pInterface->m_pNext;
		}

		for (auto name : interfaceNames)
			fout << '\t' << name << '\n';

		fout << '\n';
		interfaceNames.clear();
	}
	std::cout << "Interfaces.txt generated!\n";
}

void SaveGameSystemsToFile(std::ofstream& fout) {
	using namespace std;

	struct IGameSystemFactory : public VClass {
		IGameSystemFactory* m_pNextFactory;
		const char* m_szName;
	};

	auto m_pFactory = *Memory::Scan("E8 ? ? ? ? 84 C0 74 D3 48 8D 0D", "client.dll")
		.GetAbsoluteAddress(1)
		.Offset(8)
		.GetAbsoluteAddress<IGameSystemFactory**>(3);

	set<string> names;

	while (m_pFactory) {
		if (m_pFactory->m_szName)
			names.insert(m_pFactory->m_szName);

		m_pFactory = m_pFactory->m_pNextFactory;
	}

	for (auto name : names)
		fout << name << '\n';

	std::cout << "GameSystems.txt generated!\n";
}

void SaveNetvarsToFile(std::ofstream& fout) {
	fout << std::hex;
	fout << "#pragma once\n#include <cstdint>\nnamespace Netvars {\n";
	for (auto& [className, classMap] : Netvars) {
		fout << std::format("\tnamespace {}", className) << " {\n";
		for (auto& desc : classMap)
			fout << std::format("\t\tconstexpr uint32_t {} = {:#x}; // {}\n", desc.m_name, desc.m_single_inheritance_offset, desc.m_type->m_name_);

		fout << "\t}\n";
	}
	fout << "}";

	std::cout << "Netvars.h generated!\n";
}


void HackThread(HMODULE hModule) {
	const bool console = true;

	FILE* f;
	if (console) {
		AllocConsole();
		freopen_s(&f, "CONOUT$", "w", stdout);
	}

	std::string dumpFolderPath;
	{
		char buf[256]{ 0 };
		SHGetSpecialFolderPathA(0, buf, CSIDL_PROFILE, false);
		dumpFolderPath = buf;
		dumpFolderPath += "\\Documents\\D2Dumper";
	}
	std::cout << "Removing old dump...\n";
	std::filesystem::remove_all(dumpFolderPath);
	std::filesystem::create_directory(dumpFolderPath);

	SchemaSystem = (CSchemaSystem*)CreateInterface("schemasystem.dll", "SchemaSystem_001");
	std::cout << "SchemaSystem: " << SchemaSystem << '\n';

	std::cout << "Dump started at " << getTimeStr() << std::endl << std::endl;

	clock_t timeStart = clock();

	// TODO: paste implementation from source2sdk
	// DumpAllClasses(dumpFolderPath);

	SchemaDumpToMap("client.dll",
		"CEntityIdentity",
		"C_DOTA_Item",
		"C_DOTA_Item_PowerTreads",
		"C_DOTA_BaseNPC_Hero",
		"C_DOTAPlayerController",
		"C_DOTA_UnitInventory",
		"CSkeletonInstance",
		"CModelState",
		"C_DOTABaseAbility",
		"C_DOTA_PlayerResource",
		"PlayerResourcePlayerTeamData_t",
		"PlayerResourcePlayerData_t",
		"C_DOTAGamerules",
		"CGameSceneNode",
		"C_DOTA_Item_Rune",
		"GameTime_t",
		"C_DOTA_Item_EmptyBottle",
		"C_DOTAGamerulesProxy",
		"C_DOTAWearableItem",
		"C_EconItemView",
		"C_DOTA_Item_Physical"
	);

	SchemaDumpToMap("server.dll",
		"CDOTA_Buff");

	SchemaDumpToMap("particles.dll",
		"CNewParticleEffect",
		"C_OP_RenderSprites",
		"CParticleSystemDefinition",
		"CParticleVecInput"
	);

	if (std::ofstream fout(dumpFolderPath + "\\Netvars.h"); fout.is_open()) {
		SaveNetvarsToFile(fout);
		fout.close();
	}

	if (std::ofstream fout(dumpFolderPath + "\\Interfaces.txt"); fout.is_open()) {
		SaveInterfacesToFile(fout);
		fout.close();
	}

	if (std::ofstream fout(dumpFolderPath + "\\GameSystems.txt"); fout.is_open()) {
		SaveGameSystemsToFile(fout);
		fout.close();
	}

	while (scopesDumped != scopeCount)
		Sleep(10);

	clock_t timeEnd = clock();

	std::cout << "\nTime elapsed: " << round(((double)(timeEnd - timeStart) / CLOCKS_PER_SEC) * 10) / 10 << "s" << '\n';

	if (console) {
		system("pause");
		if (f) fclose(f);
		FreeConsole();
	}
	FreeLibrary(hModule);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		std::thread(HackThread, hModule).detach();
	}

	return TRUE;
}

