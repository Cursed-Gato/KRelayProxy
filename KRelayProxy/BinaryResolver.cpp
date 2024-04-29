#include "BinaryResolver.h"
#include <vector>

BinaryResolver::BinaryResolver(std::string nameOfAssembly) {
	std::wstring nameOfAssemblyTemp = std::wstring(nameOfAssembly.begin(), nameOfAssembly.end());
	LPCWSTR lpNameOfAssemblyTemp = nameOfAssemblyTemp.c_str();

	binaryHandle = GetModuleHandleW(lpNameOfAssemblyTemp);
	this->ready = false;
	
	if (!binaryHandle) {
		std::cout << "Failed to Get Module Handle" << std::endl;
		return;
	}

	if (!GetModuleInformation(GetCurrentProcess(), binaryHandle, &binaryInfo, sizeof(MODULEINFO))) {
		std::cout << "Failed to Get ModuleInformation" << std::endl;
		return;
	}

	this->binaryBase = reinterpret_cast<uintptr_t>(binaryInfo.lpBaseOfDll);
	this->binarySize = binaryInfo.SizeOfImage;

	std::cout << nameOfAssembly << "found" << std::endl;

	this->ready = true;
}

DWORD BinaryResolver::GetApiCall(LPCSTR functionName) {
	auto addressOfApi = (DWORD)GetProcAddress(binaryHandle, functionName);

	if (!addressOfApi) {
		std::cout << "Failed To Get Address For " << functionName << std::endl;
	}
	else {
		addressOfApi = addressOfApi - (DWORD)binaryBase;
	}

	return addressOfApi;
}

DWORD BinaryResolver::GetFunctionBySig(const char* pattern, const char* mask, int offset) {
	//returns the beggining of the sigs address In memory, relative to base + offset

	if(!this->ready)
		return 0;

	DWORD foundAddress = FindPattern(pattern, mask);

	return foundAddress - offset;
}

DWORD BinaryResolver::FindPattern(const char* pattern, const char* mask){
	//returns relative address
	DWORD patternLenght = (DWORD)strlen(mask);

	std::vector<DWORD> foundAddresses;

	for (DWORD i = 0; i < binarySize - patternLenght; ++i) {
		bool found = true;

		for (DWORD j = 0; j < patternLenght; ++j) {
			if (mask[j] != '?' && pattern[j] != *(char*)(binaryBase + i + j)) {
				found = false;
				break;
			}
		}

		if (found) {
			foundAddresses.push_back(i);
		}
	}

	if (foundAddresses.size() > 1) {
		std::cout << "Found Multiple Addresses: " << foundAddresses.size() << std::endl;
		return foundAddresses[0];
	}
	else if (foundAddresses.size() == 0) {
		std::cout << "Didnt Find Address" << std::endl;
		return 0;
	}
	else {
		return foundAddresses[0];
	}
}

DWORD BinaryResolver::FindPattern(const char* pattern, const char* mask, uintptr_t relBegin, size_t size) {
	//returns relative address
	DWORD patternLenght = (DWORD)strlen(mask);
	uintptr_t begin = binaryBase + relBegin;

	std::vector<DWORD> foundAddresses;

	for (DWORD i = 0; i < size - patternLenght; ++i) {
		bool found = true;

		for (DWORD j = 0; j < patternLenght; ++j) {
			if (mask[j] != '?' && pattern[j] != *(char*)(begin + i + j)) {
				found = false;
				break;
			}
		}

		if (found) {
			if(i != size - patternLenght - 1)
				foundAddresses.push_back(relBegin + i);
		}
	}

	if (foundAddresses.size() > 1) {
		std::cout << "Found Multiple Addresses: " << foundAddresses.size() << std::endl;
		return foundAddresses[0];
	}
	else if (foundAddresses.size() == 0) {
		std::cout << "Didnt Find Address" << std::endl;
		return 0;
	}
	else {
		return foundAddresses[0];
	}
}

std::vector<DWORD> BinaryResolver::FindPatternM(const char* pattern, const char* mask) {
	//returns relative address
	DWORD patternLenght = (DWORD)strlen(mask);

	std::vector<DWORD> foundAddresses;

	for (DWORD i = 0; i < binarySize - patternLenght; ++i) {
		bool found = true;

		for (DWORD j = 0; j < patternLenght; ++j) {
			if (mask[j] != '?' && pattern[j] != *(char*)(binaryBase + i + j)) {
				found = false;
				break;
			}
		}

		if (found) {
			foundAddresses.push_back(i);
		}
	}

	if (foundAddresses.size() > 1) {
		return foundAddresses;
	}
	else if (foundAddresses.size() == 0) {
		std::cout << "Didnt Find Address" << std::endl;
		return foundAddresses;
	}
	else {
		return foundAddresses;
	}
}

std::vector<DWORD> BinaryResolver::FindPatternM(const char* pattern, const char* mask, uintptr_t relBegin, size_t size) {
	//returns relative address
	DWORD patternLenght = (DWORD)strlen(mask);
	uintptr_t begin = binaryBase + relBegin;

	std::vector<DWORD> foundAddresses;

	for (DWORD i = 0; i < size - patternLenght; ++i) {
		bool found = true;

		for (DWORD j = 0; j < patternLenght; ++j) {
			if (mask[j] != '?' && pattern[j] != *(char*)(begin + i + j)) {
				found = false;
				break;
			}
		}

		if (found) {
			foundAddresses.push_back(relBegin + i);
		}
	}

	if (foundAddresses.size() == 0) {
		std::cout << "Didnt Find Address" << std::endl;
	}
		
	return foundAddresses;
}

DWORD BinaryResolver::getSize() {
	return this->binarySize;
}

bool BinaryResolver::checkAddressValid(uintptr_t address) {
	if (address > this->binaryBase + this->binarySize || address < this->binaryBase)
		return false;
	
	return true;
}

uintptr_t BinaryResolver::getBase() {
	return this->binaryBase;
}

bool BinaryResolver::changeMemoryProtection(uintptr_t address, size_t size, DWORD protection) {
	DWORD oldProtect;
	return VirtualProtect(reinterpret_cast<LPVOID>(address), size, protection, &oldProtect) != 0;
}


