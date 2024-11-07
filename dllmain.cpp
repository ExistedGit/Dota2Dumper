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
#include "sdk.h"
#include <TlHelp32.h>
#include <thread>

using namespace memutils;

using std::endl;
using std::cout;

std::string getTimeStr() {
	std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	char buf[50] = { 0 };
	std::strftime(buf, 50, "%d-%m-%Y %H:%M:%S", std::localtime(&now));
	return buf;
}


struct ClassDescription;

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

	CUtlTSHashV2<CSchemaClassBinding*> GetClasses() {
		return Member<CUtlTSHashV2<CSchemaClassBinding*>>(1280);
	}

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


struct SchemaClass {
	SchemaClass* parent{};
	std::string name;
	std::string dll;

	std::set<SchemaClassFieldData_t, less_than_key> fields;

	void DumpToStream(std::ostream& out, std::set<SchemaClass*>& alreadyDumped) {
		if (alreadyDumped.contains(this)) return;

		alreadyDumped.insert(this);

		if (parent) parent->DumpToStream(out, alreadyDumped);

		// Module, then inheritance chain

		out << "\t// " << dll << std::endl;

		out << "\t// " << name;
		auto pParent = parent;
		while (pParent) {
			out << " < " << pParent->name;
			pParent = pParent->parent;
		}
		out << std::endl;

		out << std::format("\tnamespace {} {{\n", name);

		if (parent)
			out << std::format("\t\tusing namespace {};\n\n", parent->name);

		for (auto& field : fields)
			// ex: constexpr netvar_t m_bIsInAbilityPhase = /* 0x598, bool */ { "client.dll", "CDOTA_BaseAbility", "m_bIsInAbilityPhase" };
			out << std::format(
				"\t\tinline netvar_t {} = /* {:#x}, {} */ {{ \"{}\", \"{}\", \"{}\" }};\n",
				field.m_name,
				field.m_single_inheritance_offset,
				field.m_type->m_name_,

				dll,
				name,
				field.m_name
			);

		out << "\t}\n";
	}
};

std::unordered_map<std::string, SchemaClass> Netvars;

class CSchemaSystem : public VClass {
public:
	CSchemaSystemTypeScope* GlobalTypeScope(void) {
		return CallVFunc<11, CSchemaSystemTypeScope*>();
	}

	CSchemaSystemTypeScope* FindTypeScopeForModule(const char* m_module_name) {
		return CallVFunc<13, CSchemaSystemTypeScope*>(m_module_name);
	}

	CUtlVector<CSchemaSystemTypeScope*> GetTypeScopes() const {
		return Member<CUtlVector<CSchemaSystemTypeScope*>>(0x188);
	}
	static CSchemaSystem* GetInstance() {
		static CSchemaSystem* inst = (CSchemaSystem*)CreateInterface("schemasystem.dll", "SchemaSystem_001");
		return inst;
	}
};

inline void DumpClassMembers(CSchemaClassInfo* classDesc) {
	std::string className = classDesc->m_name;

	if (Netvars.count(className))
		return;

	std::cout << "Dumping " << className << "...\n";

	SchemaClass schemaClass;
	for (const auto& field : classDesc->GetFields()) {
		schemaClass.fields.insert(field);
	}
	schemaClass.dll = classDesc->m_type_scope->GetScopeName();
	schemaClass.name = classDesc->GetName();

	if (classDesc->GetBaseClass()) {
		DumpClassMembers(*classDesc->GetBaseClass());

		schemaClass.parent = &Netvars[(*classDesc->GetBaseClass())->m_name];
	}

	Netvars[className] = schemaClass;
}

template<typename... Args>
void SchemaDumpToMap(std::string_view _module, Args&&... args) {
	const char* classes[sizeof...(args)] = { std::forward<Args>(args)... };
	auto typeScope = CSchemaSystem::GetInstance()->CallVFunc<13, CSchemaSystemTypeScope*>(_module.data(), nullptr); // second arg is a buffer for something

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
	fout << endl;

	if (classDesc->m_fields_size == 0)
		fout << "<no members>\n";
	else
		for (uintptr_t i = 0; i < classDesc->m_fields_size; i++) {
			SchemaClassFieldData_t field = classDesc->m_fields[i];
			fout << std::format("\t{} {} {:#x};\n", field.m_type->m_name_, field.m_name, field.m_single_inheritance_offset);
		}
	fout << endl;
}

struct InterfaceInfo {
	void(*CreateInterface)();
	const char* m_szName;
	InterfaceInfo* m_pNext;
};

void DumpAllClasses(const std::string& dir) {
	auto scopes = CSchemaSystem::GetInstance()->GetTypeScopes();
	scopeCount = scopes.size();

	for (auto scope : scopes) {
		std::thread([&, scope]() {
			auto classes = scope->GetClasses();
			std::filesystem::create_directory(dir + "\\" + scope->GetScopeName().data());
			auto _cl = classes.GetElements();
			for (const auto _class : _cl) {
				std::ofstream fout(dir + "\\" + scope->GetScopeName().data() + "\\" + _class->m_name + ".txt");

				const auto classDesc = scope->FindDeclaredClass(_class->m_name);
				std::set<std::string> parents;
				DumpClassToText(classDesc, fout, parents);

				fout.close();
			}
			++scopesDumped;
			}).detach();
	}
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

		for (auto& name : interfaceNames)
			fout << '\t' << name << endl;

		fout << endl;
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

	auto m_pFactory = *Memory::Scan("E8 ? ? ? ? 84 C0 74 D3", "client.dll")
		.GetAbsoluteAddress(1)
		.Offset(50)
		.GetAbsoluteAddress<IGameSystemFactory**>(3);

	set<string> staticFactories, reallocatingFactories;

	while (m_pFactory) {
		if (m_pFactory->m_szName) {
			if (m_pFactory->CallVFunc<9>())
				staticFactories.insert(m_pFactory->m_szName);
			else
				reallocatingFactories.insert(m_pFactory->m_szName);
		}

		m_pFactory = m_pFactory->m_pNextFactory;
	}
	const auto printHeader = [](ostream& out, const std::string& header) {
		const int width = 20;
		for (int i = 0; i < width; i++)out << "/";
		out << endl;

		out << "//";

		int spaces = (width - 2 * 2 - header.size()) / 2;
		for (int i = 0; i < spaces; i++) out << ' ';

		out << header;

		for (int i = 0; i < spaces; i++) out << ' ';

		out << "//" << endl;

		for (int i = 0; i < width; i++)out << "/";
		out << endl;
		};

	printHeader(fout, "STATIC");
	for (auto& name : staticFactories)
		fout << name << endl;

	fout << endl;

	printHeader(fout, "REALLOCATING");
	for (auto& name : reallocatingFactories)
		fout << name << endl;

	std::cout << "GameSystems.txt generated!\n";
}

void SaveNetvarsToFile(std::ofstream& fout) {
	fout << std::hex;
	fout
		<< "#pragma once\n"
		<< "#include <cstdint>\n"
		<< "#include <optional>\n"
		<< "\n// Generated at " << getTimeStr() << "\n"
		<< "// D2C Netvars: existence checked at compile time, offset lazily evaluated\n"
		<< "\n" R"(class netvar_t {
	std::string_view dll, name, member;

	std::optional<uint16_t> offset;
public:
	constexpr netvar_t(std::string_view dll, std::string_view name, std::string_view member)
		: dll(dll), name(name), member(member)
	{}

	uint16_t GetOffset();

	operator uint16_t() {
		return GetOffset();
	}
};)"
"\n"
<< "\nnamespace Netvars {\n";


	std::set<SchemaClass*> alreadyDumped;
	for (auto& [className, schemaClass] : Netvars) {
		schemaClass.DumpToStream(fout, alreadyDumped);
	}
	fout << "}";

	std::cout << "Netvars.h generated!\n";
}


static void HackThread(HMODULE hModule) {
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

	std::cout << "SchemaSystem: " << CSchemaSystem::GetInstance() << endl;

	std::cout << "Dump started at " << getTimeStr() << std::endl << std::endl;

	clock_t timeStart = clock();

	DumpAllClasses(dumpFolderPath);

	auto scopes = CSchemaSystem::GetInstance()->GetTypeScopes();
	for (auto scope : scopes) {
		std::cout << scope->GetScopeName() << std::endl;
	}

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

	std::cout << "\nTime elapsed: " << round(((double)(timeEnd - timeStart) / CLOCKS_PER_SEC) * 10) / 10 << "s" << endl;

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

