#ifndef _MAIN_H_
#define _MAIN_H_

#pragma once

///////////////////////////////////////////////
//   ________        .__   .__   .__         //
//  /  XPL0_/  ____  |  |  |  |  |__| ____   //
// /   \  ____/ __ \ |  |  |  |  |  |/    \  //
// \    \_\  \  ___/ |  |__|  |__|  |   |  \ //
//  \______  /\___  >|____/|____/|__|___|  / //
//         \/     \/                     \/  //
///////////////////////////////////////////////

#include <iostream>
#include <Windows.h>

void hkRenderHelperCodeCave();
void hkUnknownOutgoingCodeCave();

void hookRenderMenuAsServer(byte* TeamViewerBaseAddress);
void hookUnknownFuncAsClient(byte* TeamViewerBaseAddress);

DWORD WINAPI dwMain(LPVOID lpArg);
BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved);

/*
	Attempts to find address based on a matching (@pattern, and @mask),
	starts search at @start and ends at @start+@size

	@param start
	@param size
	@param pattern
	@param mask

	@return byte* match | NULL no match
*/
byte* FindPattern(byte* start, int size, byte* pattern, char* mask)
{
	for (int i = 0; i < size; i++)
	{
		bool found = true;
		for (int j = 0; mask[j]; j++)
		{
			if (mask[j] != '?' && pattern[j] != start[i + j])
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			return (byte*)&start[i];
		}
	}

	return NULL;
}

/*
	Creates a JMP in code in memory from the @origin to the @destination, 
	return address and function return are @length+@origin

	@param origin
	@param destination
	@parmam length

	@return byte* retrun address
*/
byte* CreateJumpTo(byte* orgin, byte* destination, int length)
{
	DWORD oldProtect;
	VirtualProtect(orgin, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	*orgin = 0xE9; //JMP
	*(DWORD*)(orgin + 1) = (DWORD)(destination - orgin - 5);

	VirtualProtect(orgin, 5, oldProtect, &oldProtect);

	return orgin + length;
}

#endif
