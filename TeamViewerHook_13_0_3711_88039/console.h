#ifndef _CONSOLE_H_
#define _CONSOLE_H_

#pragma once

#include <iostream>
#include <Windows.h>

#define BANNER "///////////////////////////////////////////////\n" \
				"//   ________        .__   .__   .__         //\n" \
				"//  /  XPL0_/  ____  |  |  |  |  |__| ____   //\n" \
				"// /   \\  ____/ __ \\ |  |  |  |  |  |/    \\  //\n" \
				"// \\    \\_\\  \\  ___/ |  |__|  |__|  |   |  \\ //\n" \
				"//  \\______  /\\___  >|____/|____/|__|___|  / //\n" \
				"//         \\/     \\/                     \\/  //\n" \
				"///////////////////////////////////////////////\n\n"

class Console 
{
	private:
		FILE* fPtr;
	public:
		Console(std::string defaultText = "", std::string windowTitle = "Console v0.1")
		{
			AllocConsole();
			freopen_s(&fPtr, "CONOUT$", "w", stdout);

			SetConsoleTitle(windowTitle.c_str());

			if (defaultText.empty() == false)
			{
				printf_s(defaultText.c_str());
			}
		}
		~Console()
		{
			fclose(fPtr);
			FreeConsole();
		}
};

#endif
