#pragma once
#include "CommonCRT.h"
#include <Psapi.h>
#include <vector>

class BinaryResolver {
public:
	BinaryResolver(std::string nameOfAssembly);

	DWORD GetApiCall(LPCSTR functionName);
	DWORD GetFunctionBySig(const char* pattern, const char* mask, int offset);
	DWORD FindPattern(const char* pattern, const char* mask);
	DWORD FindPattern(const char* pattern, const char* mask, uintptr_t begin, size_t size);
	std::vector<DWORD> FindPatternM(const char* pattern, const char* mask);
	std::vector<DWORD> FindPatternM(const char* pattern, const char* mask, uintptr_t relBegin, size_t size);
	uintptr_t getBase();
	DWORD getSize();
	bool changeMemoryProtection(uintptr_t address, size_t size, DWORD protection);
	bool checkAddressValid(uintptr_t address);

private:
	bool ready;
	HMODULE binaryHandle;
	MODULEINFO binaryInfo;
	uintptr_t binaryBase;
	DWORD binarySize;
	//BaseAdress to Game Assembly
	//How much to search
};