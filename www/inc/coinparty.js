/*  CoinParty - JavaScript Helpers
    Collection of JavaScript helper functions used by other web pages.

    Copyright (C) 2016 Roman Matzutt, Henrik Ziegeldorf

    This file is part of CoinParty.

    CoinParty is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CoinParty is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CoinParty.  If not, see <http://www.gnu.org/licenses/>. */


/* Requires global variables:
 * - time
 */
function updateRemainingTime() {
	var field = document.getElementById("win");
	if (field == null) {
		return;
	}
	var mins = Math.floor(time / 60).toString();
	var secs = (time % 60).toString();
	field.value = "" + mins + "m " + secs + "s";
	if (time > 0) {
		time -= 1;
	}
}

/* Requires global variables:
 * - phase
 */
phase_letter = ['N', 'E', 'W', 'I', 'S', 'H'];
function updatePhaseMeter() {
	phasebar_items = document.getElementById("phasebar").children;
	for (i = 1; i <= 6; i++) {
		if (phase >= i) {
			phasebar_items[i-1].childNodes[0].innerHTML = phase_letter[i-1];
			phasebar_items[i-1].className = phasebar_items[i-1].className + " p" + i;
		}
		if (phase == i) {
			phasebar_items[i-1].style.border = "3px solid #D00";
			phasebar_items[i-1].style.zIndex = 2;
			phasebar_items[i-1].style.color = "#D00";
		} else {
			phasebar_items[i-1].style.zIndex = 1;
		}
	}
	return;
}

function apiRequest(peer_address, request_string) {
	var xmlHttp = null;
	xmlHttp = new XMLHttpRequest();
	console.log('Peer address: ' + peer_address[0]);
	xmlHttp.open( "GET", peer_address[0] + '/api/' + request_string, false );
	xmlHttp.send( null );
	return xmlHttp.responseText;
}

function verifySession(objects, peer_addresses, session_id, escrow, value) {
	var report;
	console.log('Objects:\n' + objects);
	for (i = 0; i < peer_addresses.length; i++) {
		var response = apiRequest(peer_addresses[i], '?msg=verify&sid=' + session_id + '&escrow=' + escrow + '&value=' + value);
		console.log('response: ' + response);
		report = JSON.parse(response);
		objects[i].innerHTML = getFormattedReport(report, session_id, peer_addresses[i]);
		console.log(report);
	}
}

var good = '<div class="true">&#x2713;</div>';
var bad = '<div class="false">&#x2717;</div>';
function getFormattedReport(report, session_id, peer_address) {
	var logo = ((report['ack'] == 'true') ? good : bad);
	var pin = ((report['pin'] == undefined) ? '---' : '(' + report['pin'] + ')');
	return '<li>' + logo +' <div style="display:inline-block"><a href="' + peer_address[0] + '/verify?sid=' + session_id + '">' + peer_address[1] + '</a><br /><span style="font-size:0.5em">' + pin + '</span></div></li>\n';
}
