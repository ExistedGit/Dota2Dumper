#include <iostream>
#include <fstream>

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
	cout << string(text.size(), '=') << endl << text << endl << string(text.size(), '=') << endl;
}
void ExitWithError(std::string_view text) {
	cout << "Error: " << text << "!" << endl;
	exit(0);
}

int main(int argc, char** argv) {
	if (argc == 1) {
		ExitWithError("Path to steamapps/common/dota 2 beta not provided");
	}

	PrintHeader("VIRTUAL TABLES");

	string d2dir = argv[1];

	ifstream fin(R"(vmt_signatures.json)");
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
			auto vmtMap = rtti::RTTI::_FindVMTs(img);

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

					auto func = PatternScanInSection(img, ".text", ParseCombo(sig));

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

					auto idx = vmtMap[vmt].GetIndexOfMethod(func);
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
