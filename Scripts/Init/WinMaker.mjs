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
*   along with program.  If not, see <http://www.gnu.org/licenses/>.  *
*                                                                          *
*                                                                          *
|**************************************************************************|
*                                                                          *
*   Author(s)     : Neo-Mind                                               *
*   Created Date  : 2021-10-01                                             *
*   Last Modified : 2024-08-01                                             *
*                                                                          *
\**************************************************************************/

//
// Handles modification of arguments to Window creation call
// =========================================================
//
// MODULE_NAME => WINMKR
// -----------------------

///
/// \brief Exported data members
///
export var WndAddr;

///
/// \brief Local data members
///
const self = 'WINMKR';

const Codes = new Map();
const FillMaps = new Map();
const TgtMaps = new Map();
var HookAddr;

var ErrMsg;
var Valid;

///
/// \brief Initialization Function
///
export function init()
{
	HookAddr = -1;
	WndAddr = -1;
	Codes.clear();
	FillMaps.clear();
	TgtMaps.clear();

	ErrMsg = null;
	Valid = null;
}

///
/// \brief Loads the necessary address
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

	$$(_, 1.3, `Initialize [Valid] to false`)
	Valid = false;

	$$(_, 2.1, `Get the CreateWindowExA function`)
	ROC.findImports();

	$$(_, 2.2, `Find the location where the client window gets created`)
	const code = ROC.FullVer == 14.29 ?
	(
		PUSH([EBP, WCn])     //push dword ptr [local.x] ; Style
	+	PUSH([POS4WC])       //push dword ptr [addr]    ; Win Name
	+	PUSH([EBP, WCn])     //push dword ptr [local.y] ; Class Name
	):
		PUSH(" 00 00 C? 02") //push <Style>
	;

	let addr = Exe.FindHexN( CALL([ROC.CreateWin]) ).find( addr =>
	{
		const found = Exe.FindLastHex(code, addr, addr - 0x20);
		return (found > 0);
	});

	if (addr == undefined)
	{
		$$(_, 2.25, `Fallback - the CALL may already have been redirected to a stub by an earlier patcher run`)
		///  The 2026-02-19 base exe is a client that has already been through WARP once: the
		///  'call dword ptr [<&USER32.CreateWindowExA>]' at 0x00E585C7 was rewritten to
		///  'call <stub> / nop', and the stub (0x03DE9F37) ends in 'jmp dword ptr [<&CreateWindowExA>]'.
		///  So no direct IAT CALL survives anywhere near the argument PUSHes and the search above
		///  comes up empty even though the creation site is exactly where it always was.
		///
		///  Detect that case by looking for the same argument PUSHes followed by a relative CALL
		///  whose target reaches an indirect JMP through the CreateWindowExA IAT slot. Re-pointing
		///  that CALL is equivalent to hooking the original one (both are 6 bytes: E8+rel32+nop),
		///  and setup() below rebuilds the whole stub from the currently staged patches, so the
		///  old one simply falls out of the chain.
		const jmpToWin = JMP([ROC.CreateWin]);
		const argEnd = code.byteCount();

		Exe.FindHexN(code).find( argAddr =>
		{
			const callAddr = Exe.FindHex(CALL(ALLWC), argAddr + argEnd, argAddr + argEnd + 0x20);
			if (callAddr < 0)
				return false;

			const stubVir = Exe.GetTgtAddr(callAddr + 1);
			if (stubVir <= 0)
				return false;

			const stubPhy = Exe.Vir2Phy(stubVir);
			if (stubPhy <= 0)
				return false;

			if (Exe.FindHex(jmpToWin, stubPhy, stubPhy + 0x40) < 0)
				return false;

			addr = callAddr; //point to the CALL itself, same as the direct match does
			return true;
		});
	}

	///  NOTE: both throws below used to assign to 'Error' instead of 'ErrMsg'. That left ErrMsg
	///  null, so the *second* load() call for the same session took the 'Valid == false' shortcut
	///  at step 1.2 and did 'throw null' - which the host reports as the useless
	///  "TypeError: Type error" instead of the real reason. Purely a typo, fixed here.
	if (addr == undefined)
		throw Log.rise(ErrMsg = new Error("Window creation CALL missing"));

	$$(_, 2.3, `Save the address`)
	HookAddr = addr;

	$$(_, 2.4, `Find the assignment of the CALL result`)
	addr = Exe.FindHex(MOV([POS4WC], EAX), addr, addr + 16);
	if (addr < 0)
		throw Log.rise(ErrMsg = new Error("Result Assignment missing"));

	$$(_, 2.5, `Save the location`)
	WndAddr = Exe.GetInt32(addr + 1);

	$$(_, 2.6, `Set [Valid] to true`)
	return Log.rise(Valid = true);
}

///
/// \brief Stage the code specified for the patch
///
export function stage(patchName, code, fillMap = null, tgtMap = null) //fillMap should contain only relative offsets, tgtMap will be as usual but without the 'start'
{
	if (Codes.has(patchName))
		return false;

	Codes.set(patchName, code);
	FillMaps.set(patchName, fillMap);
	TgtMaps.set(patchName, tgtMap);

	setup();

	return true;
}

///
/// \brief Unstage the changes specified earlier
///
export function unstage(patchName)
{
	if (!Codes.has(patchName))
		return false;

	Codes.delete(patchName);
	FillMaps.delete(patchName);
	TgtMaps.delete(patchName);

	if (Codes.size > 0)
	{
		Exe.ActivePatch = Codes.keys().next().value;
		setup();
	}

	return true;
}

///
/// \brief Local function to setup the changes
///
function setup()
{
	const _ = self + ' :: setup : ';

	$$(_, 1.1, `Merge the codes`)
	let parts = [];
	for (const [, code] of Codes)
		parts.push(code);

	parts.push( JMP([ROC.CreateWin]) );

	$$(_, 1.2, `Start the tag`)
	Exe.BeginTag("New_Win_Maker", true);

	$$(_, 1.3, `Allocate space for it`)
	const [free, freeVir] = Exe.Allocate(parts.byteCount());

	$$(_, 2.1, `Fill in respective blanks if any`)
	const offsets = MapAddrs(freeVir, parts);

	let i = 0;
	for (let [patchName, fillMap] of FillMaps)
	{
		if (fillMap)
		{
			let finalMap = {};
			for (const key in fillMap)
				finalMap[key] = fillMap[key] + offsets[i];

			parts[i] = SwapFillers(parts[i], finalMap);
		}

		let tgtMap = TgtMaps.get(patchName);
		if (tgtMap)
		{
			parts[i] = SetFillTargets(parts[i], Object.assign({start : offsets[i]}, tgtMap));
		}
		i++;
	}

	$$(_, 2.2, `Add at allocated space`)
	Exe.SetHex(free, parts.join(''));

	$$(_, 2.3, `Update the CALL`)
	Exe.SetCALL(HookAddr, freeVir, 1);
}

///
/// \brief Tester
///
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
		ShowAddr("\tHookAddr", HookAddr);
		ShowAddr("\tWndAddr", WndAddr, VIRTUAL);
		Info("}");
		return true;
	}
}