#include "main.h"
#include "classes.h"
#include "console.h"

//Console instance
Console* console;

//Dynamic return address(s) set in thread, used in naked hook(s)
DWORD g_RenderFuncReturnAddress = NULL, g_UnknownFuncRetrunAddress = NULL;

//Dynamic ptr(s) obtained in the naked hook(s) and used in the local thread
DWORD g_pRenderMenuPerms = NULL, g_pUnkOutgoingPerms = NULL;

/*
Entry Point, starts main thread on injection

@return TRUE
*/
BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//Initialize instance of the the console
		std::string info = "\nINFO - Made on Windows 10 using TeamViewer x86 Version 13.0.5058\n";
		console = new Console(std::string(BANNER) + info, std::string("TeamViewer Permissions Hook v1"));

		//Start main thread
		DWORD dwThreadID = 0;
		CreateThread(NULL, NULL, &dwMain, NULL, NULL, &dwThreadID);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		//Free console
		delete console;
	}
	return TRUE;
}

/*
Main Thread

@return [h4x success]
*/
DWORD WINAPI dwMain(LPVOID lpArg)
{
	byte* TeamViewerBaseAddress = (byte*)GetModuleHandle("TeamViewer.exe");
	printf_s("TeamViewerBaseAddress: 0x%X\n", (DWORD)TeamViewerBaseAddress);

	printf_s("Press [NUMPAD 1] if you are the Host/Server\n");
	printf_s("Press [NUMPAD 2] if you are the Client\n");

	while (1)
	{
		if (GetAsyncKeyState(VK_NUMPAD1) & 1)
		{
			printf_s("Hooking Render Menu As Server!\n");
			hookRenderMenuAsServer(TeamViewerBaseAddress);
			break;
		}

		if (GetAsyncKeyState(VK_NUMPAD2) & 1)
		{
			printf_s("Hooking Unknown Func as client!\n");
			hookUnknownFuncAsClient(TeamViewerBaseAddress);
			break;
		}
		Sleep(20);
	}

	return TRUE;
}

/*
	@description Hook routine to obtain the pointer used to enable/disable menu item options on the right side pop-up menu
	when you are the Server. Most useful so far to enable the "switch sides" feature which is normally only active
	after you have already authenticated control with the client, and initiated a change of control/sides.

	@procedure Dynamically obtains hook address via signature scan/pattern applies the hook, waits for the function to be called,
	steals ptr from register, and modifys permissions structure using pointer.

	@return void
*/
void hookRenderMenuAsServer(byte* TeamViewerBaseAddress)
{
	byte* renderMenuHookAddress = NULL;
	cTeamViewerPermissions* pTeamViewerPermissions = NULL;

	//Dyamically find address(s) using a code signature/pattern
	renderMenuHookAddress = FindPattern(TeamViewerBaseAddress,
		0xF000000,
		(byte*)"\x8B\x45\xD4\x8B\x38\x8B\x07\x8B\xB0\x94\x00\x00\x00\x8B\xCE\xFF", //8B 45 D4 8B 38 8B 07 8B B0 94 00 00 00 8B CE FF
		"xxxxxxxxxxxxxxxx");

	if (renderMenuHookAddress == NULL)
	{
		MessageBoxA(0, "Failed to find render hook address", 0, 0);
		return;
	}

	printf_s("renderMenuHookAddress: 0x%X\n", (DWORD)renderMenuHookAddress);
	printf_s("Hooking Render Func and waiting on PTR\n");

	//Create a JMP/detour/code-cave to the naked function prototype
	g_RenderFuncReturnAddress = (DWORD)CreateJumpTo((byte*)renderMenuHookAddress, (byte*)&hkRenderHelperCodeCave, 5);

	while (g_pRenderMenuPerms == NULL)
	{
		Sleep(200);
	}

	printf_s("Render func ptr 0x%X\n", g_pRenderMenuPerms);

	//Set All Permissions via direct memory accesss to the class/struct
	pTeamViewerPermissions = (cTeamViewerPermissions*)g_pRenderMenuPerms;

	if (pTeamViewerPermissions)
	{
		printf_s("Setting Server Side menu permissions!\n");

		pTeamViewerPermissions->AddContact = TRUE;
		pTeamViewerPermissions->AssignAsPresenter = TRUE;
		pTeamViewerPermissions->SwitchSides = TRUE;
		pTeamViewerPermissions->AssignAsOrganizer = TRUE;
		pTeamViewerPermissions->CloseConnection = TRUE;
		pTeamViewerPermissions->RemoveParticipant = TRUE;
		pTeamViewerPermissions->ConnectionInfo = TRUE;
		pTeamViewerPermissions->SendChatMessage = TRUE;
		pTeamViewerPermissions->bToggleAllowVideo;
		pTeamViewerPermissions->bToggleAllowChat = TRUE;
		pTeamViewerPermissions->bToggleAllowFileSharing = TRUE;
		pTeamViewerPermissions->bToggleAllowPointing = TRUE;
		pTeamViewerPermissions->bToggleAllowDrawing = TRUE;
		pTeamViewerPermissions->AllowVideo = TRUE;
		pTeamViewerPermissions->AllowChat = TRUE;
		pTeamViewerPermissions->AllowFileSharing = TRUE;
		pTeamViewerPermissions->AllowPointing = TRUE;
		pTeamViewerPermissions->AllowDrawing = TRUE;
		pTeamViewerPermissions->AllowControl = TRUE;
		pTeamViewerPermissions->bToggleAllowControl = TRUE;
		pTeamViewerPermissions->EditName = TRUE;
	}
}

/*
	@description Hook routine to obtain the pointer used when you are connected to someone and would like to take control 
	of the mouse/keyboard even if their settings don't allow it, and/or the current permissions on their side
	"suggest" control is disabled.

	@procedure Dynamically obtains hook address via signature scan/pattern applies the hook, waits for the function to be called,
	steals ptr from register, and modifys permissions structure using pointer.

	@return void
*/
void hookUnknownFuncAsClient(byte* TeamViewerBaseAddress)
{
	cTVPerm2* pTVPerms2 = NULL;
	byte* unknownOutgoingHookAddress = NULL;
	
	//Dyamically find address(s) using a code signature/pattern
	unknownOutgoingHookAddress = FindPattern(TeamViewerBaseAddress,
		0xF000000,
		(byte*)"\x8B\xBB\x6C\x01\x00\x00\x8B\x07\x8B\x70\x1C\x8B\xCE", //8B BB 6C 01 00 00 8B 07 8B 70 1C 8B CE
		"xxxxxxxxxxxx");

	if (unknownOutgoingHookAddress == NULL)
	{
		MessageBoxA(0, "Failed to find outgoing hook address", 0, 0);
		return;
	}

	printf_s("unknownOutgoingHookAddress: 0x%X\n", (DWORD)unknownOutgoingHookAddress);
	printf_s("Hooking Unknown Func and waiting on PTR\n");

	//Create our JMP/detour/code-cave to our Code Cave prototype
	g_UnknownFuncRetrunAddress = (DWORD)CreateJumpTo((byte*)unknownOutgoingHookAddress, (byte*)&hkUnknownOutgoingCodeCave, 6);

	while (g_pUnkOutgoingPerms == NULL)
	{
		Sleep(200);
	}

	printf_s("Unknown func ptr 0x%X\n", g_pUnkOutgoingPerms);

	//Set All Permissions via direct memory accesss to the class/struct
	pTVPerms2 = (cTVPerm2*)g_pUnkOutgoingPerms;
	if (pTVPerms2)
	{
		printf_s("Activating Drive Mouse!\n");
		pTVPerms2->DriveMouse = TRUE;
	}
}

/*
	Hi-jacks EDI register which contains a pointer I was unable to locate statically.

	@return JMP to original code
*/
void _declspec(naked) hkRenderHelperCodeCave()
{
	__asm
	{
		//mov eax, [ebp+var_2C]
		_emit 0x8B 
		_emit 0x45 
		_emit 0xD4

		//mov edi, [eax]
		_emit 0x8B 
		_emit 0x38
		
		PUSHAD
		MOV g_pRenderMenuPerms, EDI //Hi-Jack pointer from EDI
	}

	__asm
	{
		POPAD
		JMP g_RenderFuncReturnAddress
	}
}

/*
Hi-jacks EDI register which contains a pointer I was unable to locate statically, 

@return JMP to original code
*/
void _declspec(naked) hkUnknownOutgoingCodeCave()
{
	__asm 
	{
		//MOV EDI, DWORD PTR DS:[EBX+16C]
		_emit 0x8B
		_emit 0xBB
		_emit 0x6C
		_emit 0x01
		_emit 0x00
		_emit 0x00
		PUSHAD

		MOV g_pUnkOutgoingPerms, EDI //Hi-Jack pointer from EDI
	}

	__asm
	{
		POPAD
		JMP g_UnknownFuncRetrunAddress
	}
}