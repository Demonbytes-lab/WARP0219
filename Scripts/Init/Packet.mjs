/**************************************************************************\
*                                                                          *
*   Copyright (C) 2021-2024 Neo-Mind                                       *
*                                                                          *
*   This file is a part of WARP project                                    *
*                                                                          *
*   WARP is free software: you can redistribute it and/or modify           *
*   it under the terms of the GNU General Public License as published by   *
*   the Free Software Foundation, either version 3 of the License, or      *
*   (at your option) any later version.                                    *
*                                                                          *
*   This program is distributed in the hope that it will be useful,        *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
*   GNU General Public License for more details.                           *
*                                                                          *
*   You should have received a copy of the GNU General Public License      *
*   along with program.  If not, see <http://www.gnu.org/licenses/>.       *
*                                                                          *
*                                                                          *
|**************************************************************************|
*                                                                          *
*   Author(s)     : Neo-Mind                                               *
*   Created Date  : 2021-08-20                                             *
*   Last Modified : 2024-08-01                                             *
*                                                                          *
\**************************************************************************/

//
// Stores packet keys and related patch data
// =========================================
//
// MODULE_NAME => PACKET
// -----------------------

///
/// \brief Exported data members
///


/**Keys pushed as argument**/
export const Pusher  = 0;

/**Direct value movement inside Function**/
export const Mover   = 1;

/**Direct movement with common value for 2 or all 3 keys**/
export const Sharer  = 2;

/**Virtualized function (need to use an explicit mapping instead) OR
 * It is only assigning zeros.**/
export const Virtual = 3;

/**Function with unknown signature**/
export const Unknown = 4;

/**tag name to use for shared changes**/
export const Tag = 'EncKeys';


/**The VIRTUAL address of the function which sets the keys and/or does the obfuscation**/
export var KeySetter;

/**One of the types mentioned above**/
export var KS_Type;

/**The code for mov ecx, dword ptr [KeyAddr]**/
export var MovECX;

/**Location where the keys are assigned inside ObfuscateOrInit function**/
export var Assigner;

/**The set of Packet Keys that were extracted/mapped out**/
export var Keys;

/**True when the KeySetter function still begins with the standard 'push ebp; mov ebp, esp' frame setup.
 * ROC.HasFP only tells us whether the client as a whole was built with frame pointers - it does not
 * tell us whether this particular function still has its prologue intact. On the 2026 clients the
 * KeySetter entry has been overwritten (see step 7.2) so the two answers differ.**/
export var HasFrame;


///
/// \brief Local data members
///
const self = 'PACKET';

/**Will be true or false indicating extraction status**/
var Valid;

/**Will contain the Error Object with a message about the issue encountered during extraction if any**/
var ErrMsg;


///
/// \brief Initialization Function
///
export function init()
{
	KeySetter = -1;
	KS_Type = Unknown;
	MovECX = '';
	Assigner = -1;
	HasFrame = true;

	Keys = null;
	Valid = null;
	ErrMsg = null;

	Identify(self, [
		'Pusher', 'Mover', 'Sharer', 'Virtual', 'Unknown',
		'KeySetter', 'KS_Type', 'MovECX', 'Tag',
		'Keys', 'Assigner', 'NewKeys', 'HasFrame',
		'init', 'load', 'setKey', 'unsetKey', 'allocate'
	]);
}

///
/// \brief Function to extract data from loaded exe and set the members
///
export function load()
{
	const _ = Log.dive(self, 'load');

	$$(_, 1.1, `Check if load was already called`)
	if (Valid != null)
	{
		$$(_, 1.2, `Check for errors and report them again if present otherwise simply return`)
		Log.rise();

		if (Valid)
			return Valid;
		else
			throw ErrMsg;
	}

	$$(_, 1.3, `Initialize [Valid] to false && the [KS_Type] to Unknown`)
	Valid = false;
	KS_Type = Unknown;

	$$(_, 1.4, `Ensure the Build date is within valid values`)
	if (!ROC.HasPktKeys)
		throw Log.rise(ErrMsg = new Error(`${self} - Unsupported build date`));

	$$(_, 1.5, `Find where the string 'PACKET_CZ_ENTER' is PUSHed`)
	let addr = Exe.FindText("PACKET_CZ_ENTER");
	if (addr > 0)
	{
		addr = Exe.FindHex( PUSH(addr) );
	}

	if (addr < 0)
	{
		$$(_, 1.6, `If not found then look for the CALL, MOV, CALL pattern`)
		const inb4 =
			CALL(ALLWC)   //call func#1
		+	MOV(ECX, EAX) //mov ecx, eax
		+	CALL(ALLWC)   //call func#2
		;

		const code =
			inb4          //call CRagConnection::instanceR
			              //mov ecx, eax
			              //call CRagConnection::GetPacketSize
		+	PUSH_EAX      //push EAX
		+	inb4          //call CRagConnection::instanceR
			              //mov ecx, eax
			              //call CRagConnection::SendPacket
		+	PUSH_1        //push 1
		+	inb4          //call CRagConnection::instanceR
			              //mov ecx, eax
			              //call CConnection::SetBlock
		+	PUSH(6)       //push 6
		;
		addr = Exe.FindHex(code);
	}

	if (addr < 0 && Exe.BuildDate > 20200800)
	{
		$$(_, 1.7, `In more recent clients the GetPacketSize & SendPacket sequences are not present,`)
		$$(_, 1.7, `so we look for the RegSetValueExA CALL for CASH_CATEGORY as reference.`)

		const ccAddr = Exe.FindText("CASH_CATEGORY");
		if (ccAddr > 0)
		{
			const code =
				PUSH(4)      //push 4                      ; Type = REG_DWORD
			+	PUSH_0       //push 0                      ; Reserved
			+	PUSH(ccAddr) //push offset "CASH_CATEGORY" ; SubKey
			;
			addr = Exe.FindHex(code);
		}
	}

	/**==================================================================
	2026 clients : every route above is string keyed and all 3 strings
	are gone from the searchable data sections -

	  'PACKET_CZ_ENTER' - absent (it was already absent on 2025-07-16)
	  'CASH_CATEGORY'   - still present in .rdata but the copy used by
	                      this very function is one of the inline XOR
	                      encrypted literals (decrypted at 00D9661E on
	                      2026-02-19, see Scripts/Support/EncStrings.qjs),
	                      so the PUSH of the .rdata copy is nowhere near
	                      the ObfuscateOrInit CALL any more.

	The call site itself is completely unchanged though, so anchor on its
	shape instead. The registry writing routine reads two unrelated globals
	into ECX around the CALL and then starts an inlined strcpy:

	  2025-07-16 @00D25ECF        2026-02-19 @00D963F6
	    mov  ecx, [1318A18]         mov  ecx, [1450B98]
	    call 00735830               call 0076DF40
	    mov  ecx, [15BEE9C]         mov  ecx, [16F7114]   ; g_ragConnection
	    push 1                      push 1
	    call 00AB32A0               call 00B155F0         ; ObfuscateOrInit
	    mov  ecx, [1212D04]         mov  ecx, [1348F80]

	Measured: exactly 1 match on 2025-07-16 and exactly 1 on 2026-02-19
	(dropping the trailing MOV gives 2 matches on both, so it is needed).
	==================================================================**/
	if (addr < 0)
	{
		$$(_, 1.8, `Fall back to the shape of the ObfuscateOrInit CALL site inside the registry writer`)
		const code =
			MOV(ECX, [POS4WC]) //mov ecx, dword ptr [<unrelated global>]
		+	CALL(ALLWC)        //call <unrelated func>
		+	MOV(ECX, [POS4WC]) //mov ecx, dword ptr [g_ragConnection]
		+	PUSH_1             //push 1
		+	CALL(ALLWC)        //call CRagConnection::ObfuscateOrInit
		+	MOV(ECX, [POS4WC]) //mov ecx, dword ptr [<unrelated global>]
		;

		const refAddr = Exe.FindHex(code);
		if (refAddr > 0)
			addr = refAddr + code.byteCount(); //keep the CALL inside the 0x100 window used below
	}

	if (addr < 0)
		throw Log.rise(ErrMsg = new Error(`${self} - reference location not found`));

	$$(_, 2.1, `Look for 3 PUSHes followed by a CALL (keys are PUSHed to function)`)
	let code =
		MOV(ECX, [POS3WC]) //mov ecx, dword ptr [KeyAddr]
	+	PUSH(ALLWC)        //push <key3>
	+	PUSH(ALLWC)        //push <key2>
	+	PUSH(ALLWC)        //push <key1>
	+	CALL()             //call KeySetter
	;
	let callAddr = Exe.FindHex(code, addr - 0x100, addr);
	if (callAddr > 0)
	{
		$$(_, 2.2, `If found then set the KS_Type and extract the MOV statement`)
		KS_Type = Pusher;
		MovECX = Exe.GetHex(callAddr, 6);

		$$(_, 2.3, `Extract the KeySetter address and the keys themselves`)
		callAddr += code.byteCount();
		KeySetter = Exe.GetTgtAddr(callAddr);
		Keys = [
			Exe.GetInt32(callAddr -  5),
			Exe.GetInt32(callAddr - 10),
			Exe.GetInt32(callAddr - 15)
		];

		$$(_, 2.4, `Set [Valid] to true`)
		return Log.rise(Valid = true);
	}

	$$(_, 3.1, `Look for PUSH 1, CALL pattern next (keys get assigned inside the function)`)
	code =
		MOV(ECX, [POS4WC]) //mov ecx, dword ptr [KeyAddr]
	+	PUSH_1             //push 1
	+	CALL()             //call CRagConnection::ObfuscateOrInit
	;
	callAddr = Exe.FindHex(code, addr - 0x100, addr);
	if (callAddr < 0)
		throw Log.rise(ErrMsg = new Error(`${self} - ObfuscateOrInit CALL not found`));

	$$(_, 3.2, `Extract the MOV statement`)
	MovECX = Exe.GetHex(callAddr, 6);

	$$(_, 3.3, `Extract the CALLed function address which is the [KeySetter]`)
	callAddr += code.byteCount();
	KeySetter = Exe.GetTgtAddr(callAddr);

	$$(_, 3.4, `Go inside the function`)
	const fnAddr = Exe.Vir2Phy(KeySetter, CODE);

	/**==================================================================
	The Virtual branch (step 7) hands out an [Assigner] that is meant to
	sit right after the frame setup, so that the JMP written there still
	leaves 'push ebp; mov ebp, esp' running before our replacement code.
	That only holds while the prologue is actually there.

	On 2026-02-19 CRagConnection::ObfuscateOrInit @00B155F0 no longer has
	one - its first 5 bytes read 33 C0 C2 04 00 ('xor eax, eax; retn 4'),
	i.e. the exact end state NoPacketEncr writes, with the remainder of
	the body mutated into junk plus a JMP into the packer's region. Using
	ROC.HasFP (which is true for this client) would put the JMP at +3 and
	split the 'retn 4' in half.
	==================================================================**/
	$$(_, 3.5, `Check whether the function itself still starts with a frame setup`)
	HasFrame = ROC.HasFP && Exe.GetHex(fnAddr, 3).trim() === FP_START.trim();

	$$(_, 4.1, `First look for the individual key assignment pattern`)
	const reg = Exe.Version > 11 ? EAX : ECX;
	code = MOV([reg, ' 0?'], ALLWC).repeat(3); //mov dword ptr [ecx + dispA], <Key A> ;the keys could be assigned in any order
	                                           //mov dword ptr [ecx + dispB], <Key B>
	                                           //mov dword ptr [ecx + dispC], <Key C>

	addr = Exe.FindHex(code, fnAddr, fnAddr + 0x60);
	if (addr > 0)
	{
		$$(_, 4.2, `If found then set the [KS_Type] to Mover and save the location of the first MOV as the [Assigner]`)
		Assigner = addr;
		KS_Type = Mover;

		$$(_, 4.3, `Extract the keys being assigned`)
		Keys = [];
		let ins = Instr.FromAddr(addr);
		for (let i = 0; i < 3; i++)
		{
			Keys[ins.Disp/4 - 1] = ins.Immd; //order can be any so mechanism is needed
			ins.moveToNext();
		}

		$$(_, 4.4, `Set [Valid] to true.`)
		return Log.rise(Valid = true);
	}

	$$(_, 5.1, `Next look for the shared key pattern`)
	let parts =
	[//0
		CMP(EAX, 1)              //cmp eax, 1
	+	JNE(WCp)                 //jne short _next

	,//1
		MOV(EAX, ALLWC)          //mov eax, <Key A> ; shared key

	,//2
		MOV([ECX, ' 0?'], EAX)   //mov dword ptr [ecx + dispA], eax
	+	MOV([ECX, ' 0?'], EAX)   //mov dword ptr [ecx + dispC], eax
	+	MOV([ECX, ' 0?'], ALLWC) //mov dword ptr [ecx + dispB], <Key B>
	];

	addr = Exe.FindHex(parts, fnAddr, fnAddr + 0x60);
	if (addr > 0)
	{
		$$(_, 5.2, `If found then set the [KS_Type] to <Sharer> and save the location of the first MOV as the [Assigner]`)
		Assigner = addr + parts.byteCount(0);
		KS_Type = Sharer;

		$$(_, 5.3, `Extract the shared key first`)
		let ins = Instr.FromAddr(Assigner);
		const sharedKey = ins.Immd;

		$$(_, 5.4, `Extract all the keys (little more tricky since there is a MOV EAX)`)
		Keys = [];
		for (let i = 0; i < 3; i++)
		{
			ins.moveToNext();
			Keys[ins.Disp/4 - 1] = (i < 2) ? sharedKey : ins.Immd;
		}

		$$(_, 5.5, `Set [Valid] to true.`)
		return Log.rise(Valid = true);
	}

	$$(_, 6.1, `Next look for patched version of a shared key pattern`)
	parts[1] = JMP(POS4WC);
	addr = Exe.FindHex(parts, fnAddr, fnAddr + 0x60);
	if (addr > 0)
	{
		$$(_, 6.2, `If found then set the [KS_Type] to <Mover> and save the target location of the JMP (which is the first MOV) as the [Assigner]`)
		Assigner = Exe.GetTgtAddr(addr + parts.byteCount(0, 1) - 4, PHYSICAL);
		KS_Type = Mover;

		$$(_, 6.3, `Extract the keys being assigned`)
		Keys = [];
		let ins = Instr.FromAddr(Assigner);
		for (let i = 0; i < 3; i++)
		{
			Keys[ins.Disp/4 - 1] = ins.Immd; //order can be any so mechanism is needed
			ins.moveToNext();
		}

		$$(_, 6.4, `Set [Valid] to true.`)
		return Log.rise(Valid = true);
	}

	$$(_, 7.1, `Since neither pattern matched we need to use explicit mapping`)
	KS_Type = Virtual;

	$$(_, 7.2, `Set the Assigner (skip over the frame setup only when it is really there - see step 3.5)`);
	Assigner = fnAddr + (HasFrame ? 3 : 0);

	$$(_, 7.3, `For older clients we will try to look in the KeyMap`)
	if (Exe.BuildDate <= 20180308)
	{
		const keyMap = Warp.LoadYaml("Inputs/PacketKeyMap.yml");
		if (!keyMap)
			throw Error(`${self} - Packet Key Map file is invalid`);

		$$(_, 7.4, `Retrieve the keys based on the date`)
		const arr = keyMap[Exe.BuildDate];

		$$(_, 7.5, `Ensure we have a valid array`)
		if (!IsArr(arr) || arr.length !== 3)
			throw (ErrMsg = new Error(`${self} - No patterns or mappings matched`));

		Keys = arr;
	}
	else
	{
		Keys = [0, 0, 0];
	}

	$$(_, 7.6, `For any other clients, the keys are 0 by default.`)
	return Log.rise(Valid = true);
}

///
/// \brief Tester
///
const Types = ["Pusher", "Mover", "Sharer", "Virtual", "Unknown"];
export function debug()
{
	if (Valid == null)
		load();

	if (Valid == null)
	{
		Info(self + ".ErrMsg = ", ErrMsg);
		return false;
	}
	else
	{
		Info(self, "= {");
		ShowAddr("\tKeySetter", KeySetter, VIRTUAL);
		Info("\tKS_Type =", KS_Type, "(", Types[KS_Type], ")");
		Info("\tMovECX =>", MovECX);
		Info("\tHasFrame =>", HasFrame);
		ShowAddr("\tAssigner", Assigner);
		ShowArr(true, "\tKeys", Keys.map(v => v.toHex(true)));
		Info("}");
		return true;
	}
}