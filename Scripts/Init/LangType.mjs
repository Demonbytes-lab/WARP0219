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
// Stores the language type
// ========================
//
// MODULE_NAME => LANGTYPE
// -----------------------

///
/// \brief Local data members
///
const self = 'LANGTYPE';

/**Will be true or false indicating extraction status**/
var Valid;

/**Will contain the Error Object with a message about the issue encountered during extraction if any**/
var ErrMsg;

/**The g_serviceType VIRTUAL Address**/
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
	Valid  = null;
	ErrMsg = null;

	Identify(self, ['init', 'load', 'toString', 'valueOf']);
}

///
/// \brief Locate g_serviceType on clients that no longer carry the 'america' service.
///
/// kRO dropped 'america' entirely as of the 2026-02-19 client (BuildDate 20260211):
/// neither the string nor its inline 'amer'/'ic'/'a' comparison exists any more, so
/// both landmarks this module normally uses are gone.
///
/// The servicetype selector itself is untouched - a dispatch that assigns
/// g_serviceType = 0, 1, 2, ... one case per service. So identify the global
/// structurally: the address that receives consecutive immediates from one
/// neighbourhood is g_serviceType, and nothing else in the binary looks like that.
///
/// Returns the VIRTUAL address, or -1 when no such dispatch is present.
///
function FindServiceTypeDispatch()
{
	const sites = Exe.FindHexN( MOV([POS4WC], 1) ); //mov dword ptr [g_serviceType], 1
	if (!sites || sites.length === 0)
		return -1;

	//A plain 0/1/2 test is NOT enough: ordinary 3-state mode flags match it too, and one of
	//them (0x016FC564, assigned around 0x005C8384) sits earlier in the file than the real
	//dispatch at 0x00AD2CAB - so "first match wins" silently returns the wrong global.
	//The service list is long (cases 0..20), a mode flag is not. So score every candidate by
	//how many consecutive cases it actually has and demand a real list.
	const MIN_CASES = 6;
	const WINDOW    = 0x2000;

	let best = -1, bestCount = 0;
	const seen = new Set();

	for (const at of sites)
	{
		const gvar = Exe.GetUint32(at + 2);
		if (gvar < 0x400000 || seen.has(gvar))
			continue;
		seen.add(gvar);

		$$(`checking 0x${gvar.toHex(4)} - how many consecutive dispatch cases does it have?`)
		if (Exe.FindHex( MOV([gvar], 0), at - WINDOW, at ) < 0) //needs a case 0 before it
			continue;

		let count = 2; //cases 0 and 1 confirmed
		for (let n = 2; n < 32; n++)
		{
			if (Exe.FindHex( MOV([gvar], n), at, at + WINDOW ) < 0)
				break;
			count++;
		}

		if (count > bestCount)
		{
			bestCount = count;
			best = gvar;
		}
	}
	return (bestCount >= MIN_CASES) ? best : -1;
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

	$$(_, 1.4, `Find the string 'america'`)
	let strAddr = Exe.FindText("america");
	let addr;
	if (strAddr > 0)
	{
		$$(_, 1.5, `Find where it is PUSHed`)
		addr = Exe.FindHex( PUSH(strAddr) );
		if (addr > 0)
		{
			$$(_, '1.5.1', `Move addr to location after PUSH`)
			addr += 5;
		}
		else if (ROC.FullVer == 14.29)
		{
			$$(_, 1.6, `For latest VC14 clients the string is moved to a register and then to local stack. So look for that`)
			let code =
				MOV(R32, [strAddr])              //mov regD, dword ptr [strAddr]
			+	MOV(BYTE_PTR, [EBP, NEG2WC], 0)  //mov byte ptr [LOCAL.x], 0
			;
			addr = Exe.FindHex(code);
			if (addr > 0)
			{
				$$(_, '1.6.1', `Find the pattern that is close to the langtype address assignment after the MOV`)
				code =
					PUSH(7) //push 7
				+	PUSH_R  //push regA
				+	PUSH_R  //push regB
				+	PUSH_R  //push regC
				+	CALL()  //call func#1
				;
				addr = Exe.FindHex(code, addr + 0x40, addr + 0x100);
			}
		}
		if (addr < 0)
			throw Log.rise(ErrMsg = new Error(`${self} - 'america' not used`));
	}
	else if (ROC.FullVer == 14.29)
	{
		$$(_, 2.1, `Find the string 'america' compared in parts`)
		const code =
			CMP([R32], 0x72656D61)          //cmp dword ptr [r32], 616D6572h ; 'amer'
		+	JNE(WCp)                        //jne short _skip
		+	CMP(WORD_PTR, [R32, 4], 0x6369) //cmp word ptr [r32+4], 6963h    ; 'ic'
		+	JNE(WCp)                        //jne short _skip
		+	CMP(BYTE_PTR, [R32, 6], 0x61)   //cmp byte ptr [r32+6], 61h      ; 'a'
		;

		addr = Exe.FindHex(code);
		if (addr < 0)
		{
			$$(_, '2.1.1', `No 'america' anywhere - fall back to the servicetype dispatch (2026+ clients)`)
			const gvar = FindServiceTypeDispatch();
			if (gvar < 0)
				throw Log.rise(ErrMsg = new Error(`${self} - 'america' not found in parts`));

			Value = gvar;
			Hex = Value.toHex(4);
			return Log.rise(Valid = true);
		}

		$$(_, 2.2, `Move addr to location after the code`)
		addr += code.byteCount();
	}
	else
	{
		$$(_, 2.3, `No 'america' string and not a VC14.29 build - try the dispatch as well`)
		const gvar = FindServiceTypeDispatch();
		if (gvar < 0)
			throw Log.rise(ErrMsg = new Error(`${self} - 'america' not found`));

		Value = gvar;
		Hex = Value.toHex(4);
		return Log.rise(Valid = true);
	}

	$$(_, 3.1, `Find an assignment to g_serviceType after it`)
	addr = Exe.FindHex( MOV([POS4WC], 1), addr); //mov dword ptr ds:[g_serviceType], 1
	if (addr < 0)
		throw Log.rise(ErrMsg = new Error(`${self} - g_serviceType not assigned`));

	$$(_, 3.2, `Extract the address to [Value] & save it's hex`)
	Value = Exe.GetUint32(addr + 2);
	Hex = Value.toHex(4);

	$$(_, 3.3, `Set [Valid] to true`)
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
		ShowAddr(self, Value, VIRTUAL);
		return true;
	}
}