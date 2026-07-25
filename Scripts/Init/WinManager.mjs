/**************************************************************************\
*                                                                          *
*   Copyright (C) 2021-2024 Neo-Mind                                       *
*                                                                          *
*   This file is a part of WARP project (specific to RO clients)           *
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
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
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
// Stores the Window Manager & related details
// ===========================================
//
// MODULE_NAME => WINMGR
// ---------------------

///
/// \brief Exported data members
///

/**The code for MOV ECX, g_windowMgr (more useful most of the time)**/
export var MovECX;

/**The VIRTUAL address of UIWindowMgr::MakeWindow**/
export var MakeWin;


///
/// \brief Local data members
///
const self = 'WINMGR';

/**Will be true or false indicating extraction status**/
var Valid;

/**Will contain the Error Object with a message about the issue encountered during extraction if any**/
var ErrMsg;

/**The VIRTUAL address of g_windowMgr**/
var Value;

/**It's hex in Little Endian form**/
var Hex;


///
/// \brief Initialization Function
///
export function init()
{
	Value   = -1;
	Hex     = '';
	MovECX  = '';
	MakeWin = -1;
	Valid   = null;
	ErrMsg  = null;

	Identify(self, ["MovECX", "MakeWin", 'init', 'load', 'toString', 'valueOf']);
}

///
/// \brief Locate g_windowMgr + MakeWindow on clients that no longer carry 'NUMACCOUNT'.
///
/// The 2026-02-19 client (BuildDate 20260211) dropped the string, so the usual anchor
/// is gone. The call shape survives untouched, so identify the manager structurally.
///
/// Two filters are needed - neither alone is safe, both were checked against the
/// 2026 binary with the answer confirmed out of a live process (the real g_windowMgr
/// is the global whose [0] holds the UIWindowMgr vtable):
///   * pure call-site frequency picks the WRONG global (an unrelated one had MORE sites)
///   * pure distinct-method count also picks the wrong one (a busier global has 3x more)
/// Requiring both - present in the MakeWindow shape AND used with many distinct
/// methods - leaves exactly one candidate.
///
function FindWindowMgrByShape()
{
	$$(`Collect  mov ecx, <X> ; call <Y> ; push 0 ; push 0  sites`)
	const sites = Exe.FindHexN( MOV(ECX, POS4WC) + CALL(NEG3WC) + PUSH_0 + PUSH_0 );
	if (!sites || sites.length === 0)
		return null;

	const pairs = new Map(); //"X|Y" => count
	for (const at of sites)
	{
		const gvar = Exe.GetUint32(at + 1);
		if (gvar < 0x400000)
			continue;
		const fn = Exe.GetTgtAddr(at + 6);
		const key = gvar + '|' + fn;
		pairs.set(key, (pairs.get(key) || 0) + 1);
	}
	if (pairs.size === 0)
		return null;

	$$(`For each candidate global, count how many distinct methods it is used with`)
	const scored = [];
	const seenVar = new Set();
	for (const key of pairs.keys())
	{
		const gvar = parseInt(key.split('|')[0]);
		if (seenVar.has(gvar))
			continue;
		seenVar.add(gvar);

		const calls = Exe.FindHexN( MOV(ECX, gvar) + CALL(NEG3WC) );
		const distinct = new Set();
		for (const c of calls)
			distinct.add(Exe.GetTgtAddr(c + 6));

		if (distinct.size >= 50) //a window manager has a large method surface
			scored.push({ gvar: gvar, methods: distinct.size });
	}
	if (scored.length === 0)
		return null;

	scored.sort((a, b) => b.methods - a.methods);
	const gvar = scored[0].gvar;

	$$(`Pick the method most often called in the MakeWindow shape`)
	let best = -1, bestCount = 0;
	for (const [key, count] of pairs)
	{
		const [v, fn] = key.split('|').map(x => parseInt(x));
		if (v === gvar && count > bestCount)
		{
			bestCount = count;
			best = fn;
		}
	}
	if (best < 0)
		return null;

	return { Addr: gvar, MakeWin: best };
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

	$$(_, 1.3, `Initialize [Valid] to false`)
	Valid = false;

	$$(_, 1.4, `Find the string 'NUMACCOUNT'`)
	let addr = Exe.FindText("NUMACCOUNT");
	if (addr < 0)
	{
		$$(_, '1.4.1', `Gone as of the 2026 clients - identify the manager by call shape instead`)
		const info = FindWindowMgrByShape();
		if (info == null)
			throw Log.rise(ErrMsg = new Error(`${self} - 'NUMACCOUNT' not found`));

		Value   = info.Addr;
		Hex     = Value.toHex(4);
		MovECX  = ' B9' + Hex;
		MakeWin = info.MakeWin;
		return Log.rise(Valid = true);
	}

	$$(_, 1.5, `Find where it is PUSHed`)
	let code =
		MOV(ECX, POS4WC) //mov ecx, <g_windowMgr>
	+	CALL(NEG3WC)     //call UIWindowMgr::MakeWindow
	+	PUSH_0           //push 0
	+	PUSH_0           //push 0
	+	PUSH(addr)       //push offset "NUMACCOUNT"
	;

	addr = Exe.FindHex(code);
	if (addr < 0)
	{
		code = code.replace(PUSH_0, PUSH_0 + MOV(R32, R32)); //mov regA, regB follows the first 'push 0'
		addr = Exe.FindHex(code);
	}
	if (addr < 0)
		throw Log.rise(ErrMsg = new Error(`${self} - 'NUMACCOUNT' not used`));

	$$(_, 2.1, `Extract the g_windowMgr address, compute MOV instruction & CALL function address`)
	Value   = Exe.GetUint32(addr + 1);
	Hex     = Value.toHex(4);
	MovECX  = ' B9' + Hex;
	MakeWin = Exe.GetTgtAddr(addr + 6);

	$$(_, 2.2, `Set [Valid] to true`)
	return Log.rise(Valid = true);
}

///
/// \brief Override to return the hex value
///
export function toString()
{
	return Hex;
}

///
/// \brief Override to return the numeric value
///
export function valueOf()
{
	return Value;
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
		ShowAddr("\tValue", Value, VIRTUAL);
		ShowAddr("\tMakeWin", MakeWin, VIRTUAL);
		Info("\tMovECX =>", MovECX);
		Info("}");
		return true;
	}
}