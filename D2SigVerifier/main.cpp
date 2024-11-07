#include <iostream>
#include <fstream>
#include <filesystem>

#include "rtti.h"
#include "sigscan.h"
#include "json.hpp"

using namespace std;

enum class ConColor {
	Black,
	Blue,
	Green,
	Teal,
	Red,
	Lily,
	Yellow,
	White,
	Grey,
	LightBlue,
	LightGreen,
	LightTeal,
	LightRed,
	LightLily,
	LightYellow,
	BrightWhite
};

void SetConsoleColor(ConColor text = ConColor::White, ConColor background = ConColor::Black) {
	static HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hStdOut, (WORD)(((WORD)background << 4) | (WORD)text));
};

void PrintHeader(std::string_view text) {
	cout << string(text.size() + 4, '=') << endl << string(2, ' ') << text << endl << string(text.size() + 4, '=') << endl;
}

void ExitWithError(std::string_view text) {
	cout << "Error: " << text << "!" << endl;
	exit(0);
}

void GenVMTs(const string& d2dir, const string& vmtSigPath) {
	ifstream fin(vmtSigPath);
	if (!fin.good()) ExitWithError("Could not open vmt_signatures.json");

	auto dataIn = nlohmann::json::parse(fin);
	auto dataOut = nlohmann::json();

	for (auto& [folder, dlls] : dataIn.items()) {

		SetConsoleColor(ConColor::Green);
		cout << folder << endl;
		SetConsoleColor(ConColor::BrightWhite);

		for (auto& [dll, vmts] : dlls.items()) {
			auto path = d2dir + folder + dll;
			auto img = rtti::PEImage::FromFile(path);
			auto rtti = rtti::RTTI(img);
			auto vmtMap = rtti.FindVMTs();

			SetConsoleColor(ConColor::Yellow);
			cout << "  " << dll << endl;

			for (auto& [vmt, vmtData] : vmts.items()) {
				SetConsoleColor(ConColor::LightBlue);

				cout << "    " << vmt << endl;

				string vmtName = vmtData.contains("mappedName") ? (string)vmtData["mappedName"] : vmt;

				for (auto& [method, methodData] : vmtData["methods"].items()) {
					auto& vmtDataEntry = vmtMap[vmt];

					// If it's just a string then it's a simple signature
					// Otherwise the pattern goes into a field
					auto& sig = methodData.type() == nlohmann::json::value_t::string
						? methodData
						: methodData["pattern"];

					auto func = PatternScanInSection(*img, ".text", ParseCombo(sig));

					if (!func)
						SetConsoleColor(ConColor::Red);
					else
						SetConsoleColor();

					cout << "      " << method << ": ";

					if (!func) {
						cout << "NOT FOUND\n";
						SetConsoleColor();
						continue;
					}

					if (methodData.contains("steps"))
						for (auto& step : methodData["steps"].items()) {
							if (step.value()[0] == 0) {
								func = func + step.value()[1] + 4 + *(int32_t*)(func + step.value()[1]);
							}
							else if (step.value()[1] == 1) {
								func = func + step.value()[1];
							}
						}

					auto idx = rtti.GetIndexOfMethod(vmtMap[vmt], func);
					SetConsoleColor();
					cout << idx << endl;
					SetConsoleColor(ConColor::BrightWhite);
					dataOut[vmtName][method] = idx;
				}
			}
		}
	}
	fin.close();

	SetConsoleColor();

	ofstream fout("vmt.json");
	fout << dataOut.dump(4);
	fout.close();
}

struct VPInfo {
	int response, lastError;
	uintptr_t retaddr, unk;
	int idk = 0;
	uintptr_t lpAddress, dwSize;
	uint32_t newProtect, oldProtect;
};

static void CheckSignatures(const string& d2dir, const string& sigPath) {
	using namespace std::filesystem;


	ifstream fin(sigPath);
	if (!fin.good()) ExitWithError("Could not open signatures.json");

	unordered_map<string, shared_ptr<rtti::PEImage>> dlls;

	auto data = nlohmann::json::parse(fin);

	for (auto& [module_, signatures] : data.items()) {
		for (auto& [sig, sigData] : signatures.items()) {
			if (!dlls.contains(module_)) {
				string file;
				for (recursive_directory_iterator i(d2dir + "\\game\\bin\\win64"), end; i != end; ++i)
					if (!is_directory(i->path()) && i->path().filename() == (string)module_) {
						file = i->path().string();
						break;
					}

				if (file.empty()) {
					for (recursive_directory_iterator i(d2dir + "\\game\\dota\\bin\\win64"), end; i != end; ++i)
						if (!is_directory(i->path()) && i->path().filename() == (string)module_) {
							file = i->path().string();
							break;
						}
				}

				if (file.empty())
					continue;

				dlls[module_] = rtti::PEImage::FromFile(file);
			}

			string signature;
			if (sigData.is_object()) {
				signature = sigData["signature"];
			}
			else signature = sigData;

			auto& image = dlls[module_];
			auto text = image->GetSection(".text");
			auto addr = PatternScanInSection(*image, ".text", ParseCombo(signature));
			if (addr && sigData.is_object() && sigData.contains("steps"))
				for (auto& step : sigData["steps"].items()) {
					if (step.value()[0] == 0) {
						addr = addr + step.value()[1] + 4 + *(int32_t*)(addr + step.value()[1]);
						if (!image->IsInBounds(addr)) {
							addr = 0;
							break;
						}
					}
					else if (step.value()[0] == 1) {
						addr = addr + step.value()[1];
					}
				}

			if (!addr)
				SetConsoleColor(ConColor::Red);

			std::cout << sig << ": " << hex << uppercase << addr << endl << nouppercase;

			SetConsoleColor();
		}
	}
}

int main(int argc, char** argv) {
	//if (argc == 1) {
	//	ExitWithError("Path to 'steamapps/common/dota 2 beta' not provided!");
	//}
	//string d2dir = argv[1];

	SetConsoleColor();

	string d2dir = R"(H:\SteamLibrary\steamapps\common\dota 2 beta)";

	PrintHeader("VIRTUAL TABLES");
	GenVMTs(d2dir, R"(E:\GitHub Repositories VIP\Dota2Cheat\Data\vmt_signatures.json)");
	PrintHeader("SIGNATURES");
	CheckSignatures(d2dir, R"(E:\GitHub Repositories VIP\Dota2Cheat\Data\signatures.json)");
}
