#ifndef _CLASSES_H_
#define _CLASSES_H_

#pragma once

///////////////////////////////////////////////
//   ________        .__   .__   .__         //
//  /  XPL0_/  ____  |  |  |  |  |__| ____   //
// /   \  ____/ __ \ |  |  |  |  |  |/    \  //
// \    \_\  \  ___/ |  |__|  |__|  |   |  \ //
//  \______  /\___  >|____/|____/|__|___|  / //
//         \/     \/                     \/  //
///////////////////////////////////////////////

class cTeamViewerPermissions
{
public:
	char _0x0000[156];
	__int32 AddContact; //0x009C 
	char _0x00A0[16];
	__int32 AssignAsPresenter; //0x00B0 
	char _0x00B4[16];
	__int32 SwitchSides; //0x00C4 
	char _0x00C8[16];
	__int32 AssignAsOrganizer; //0x00D8 
	char _0x00DC[16];
	__int32 CloseConnection; //0x00EC 
	char _0x00F0[16];
	__int32 RemoveParticipant; //0x0100 
	char _0x0104[16];
	__int32 ConnectionInfo; //0x0114 
	char _0x0118[16];
	__int32 SendChatMessage; //0x0128 
	char _0x012C[16];
	__int32 unk1; //0x013C 
	char _0x0140[16];
	__int32 unk2; //0x0150 
	char _0x0154[16];
	__int32 unk3; //0x0164 
	char _0x0168[16];
	__int32 bToggleAllowVideo; //0x0178 
	char _0x017C[16];
	__int32 bToggleAllowChat; //0x018C 
	char _0x0190[16];
	__int32 bToggleAllowFileSharing; //0x01A0 
	char _0x01A4[16];
	__int32 bToggleAllowPointing; //0x01B4 
	char _0x01B8[16];
	__int32 bToggleAllowDrawing; //0x01C8 
	char _0x01CC[16];
	__int32 AllowVideo; //0x01DC 
	char _0x01E0[16];
	__int32 AllowChat; //0x01F0 
	char _0x01F4[16];
	__int32 AllowFileSharing; //0x0204 
	char _0x0208[16];
	__int32 AllowPointing; //0x0218 
	char _0x021C[16];
	__int32 AllowDrawing; //0x022C 
	char _0x0230[16];
	__int32 unk4; //0x0240 
	char _0x0244[16];
	__int32 AllowControl; //0x0254 
	char _0x0258[16];
	__int32 bToggleAllowControl; //0x0268 
	char _0x026C[16];
	__int32 EditName; //0x027C 
	char _0x0280[16];
	__int32 unk5; //0x0290 
	char _0x0294[36];
	__int32 unk6; //0x02B8 
};

class cTVPerm2
{
public:
	char _0x0000[308];
	__int32 DriveMouse; //0x0134 
	//Keyboard/Mouse Clicking access  should be near by :O
};


#endif