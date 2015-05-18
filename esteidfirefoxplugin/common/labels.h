/*
 * Estonian ID card plugin for web browsers
 *
 * Copyright (C) 2010-2011 Codeborne <info@codeborne.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __LABELS_H__
#define	__LABELS_H__


label labels[] = {
	// Labels format: {"English label", "Estonian translation", "Russian translation"},
	// NB! English label should not be changed here unless the place where it is used is also changed
	// All text should be in UTF8 encoding
	
	// Certificate selection dialog:
	{"Select certificate", "Sertifikaadi valik", "Seleccionar certificado"},
	{"Certificate", "Sertifikaat", "Сеrtificado"},
	{"Type", "Tüüp", "Тipo"},
	{"Valid to", "Kehtiv kuni", "Válido hasta"},
	{"Select", "Vali",  "Seleccionar"},
	{"Cancel", "Katkesta", "Cancelar"},
	{"Details...", "Vaata...", "Detalles..."},
	{"Sign", "Allkirjasta", "Firmar"},
	{"By selecting a certificate I accept that my name and personal ID code will be sent to service provider.", "Sertifikaadi valikuga nõustun oma nime ja isikukoodi edastamisega teenusepakkujale.", "Al seleccionar un certificado acepto que mi nombre y certificado serán enviados al proveedor de servicios."},

	// PIN2 dialog and PIN pad message box:
	{"For signing enter PIN2:", "Allkirjastamiseks sisesta PIN2:", "Para firmar introduzca el PIN2:" },
	{"Tries left:", "Katseid jäänud:", "Intentos restantes:" },
	{"Incorrect PIN2! ", "Vale PIN2! ", "¡PIN2 Incorrecto! "},
	{"PIN2 blocked, cannot sign!", "PIN2 blokeeritud, ei saa allkirjastada!", "¡PIN2 bloqueado, no se puede firmar!"},
	{"Signing", "Allkirjastamine", "Firmando"},
	{"Error", "Viga", "Errir"},	
	{"For signing enter PIN2 from PIN pad", "Allkirjastamiseks sisesta PIN2 kaardilugeja sõrmistikult", "Para firmar introduzca PIN2 desde el PIN pad"}
};

#endif

