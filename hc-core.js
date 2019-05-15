/*
MIT License

Copyright (c) 2019 SiOnOu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

'use strict'

const fs = require('fs');
const mqtt = require('mqtt');
const lz = require('lz-string');
const crypto = require('crypto');
const HCipher = require('./hcrypto.js');
const Auth = require('./auth.js');
const Utilize = require('./utilize');

const hcp = new HCipher();
const auth = new Auth();
const ut = new Utilize();

var en2Plain = function (m, self_pvk, opposite_pbk) {
	try {
		const plain = hcp.dec_encryptedMsg(m, self_pvk, opposite_pbk);
		const recv = hcp.extractRecv(plain.m);
		return {'r': recv, 'a': plain.auth};
	} catch (error) {
		return -1;
	}
}

var send_cmd = function (client, type, content, ch_target, self_id, self_pvk, opposite_pbk) {
	const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(self_id, content, 'cmd', type), self_pvk, opposite_pbk, 'utf-8');
	client.publish(ch_target, msg);
	console.log(`(CMD) Send ${msg.length} bytes.`);
}

var HC = function (serv, self_id, room_id, self_pvk) {

	var client = mqtt.connect(serv);					// Instance of private channel
	var client_msg = mqtt.connect(serv);				// Instance of shared channel
	var ch_share = null;								// Topic of shared channel
	const self_id_hash = hcp.sha(self_id).slice(0, 32);	// Topic of private channel
	const room_id_hash = hcp.sha(room_id).slice(0, 32);	// Topic of private channel (friend)

	// Private channel launched
	client.on('connect', function () {
		client.subscribe(room_id_hash, function (err) {
			if (!err) {
				console.log('Listing on channel ' + room_id_hash);
				console.log('Channel of self ' + self_id_hash);
				ch_share = crypto.randomBytes(32).toString('hex');
				send_cmd(client, 'invitation', ch_share, self_id_hash, self_id, self_pvk, ut.get_key(room_id, false));
			} else {
				console.log('! Cannot listen on channel ' + room_id_hash);
				client.end();
			}
		});
	});

	// Private channel receives commands
	client.on('message', function (ch, msg) {
		const sMsg = lz.decompressFromBase64(msg.toString());
		const plain = en2Plain(sMsg, self_pvk, ut.get_key(room_id, false));

		// Invalid or un-decryptable message
		if (plain === -1) {
			// console.log('*** Unreadable message');
			return -1;
		}
		const recv = plain.r;
		console.log(`
===========================
COMMAND @ ${ch}
---------------------------
From: ${recv.sender}
Time: ${recv.time}
Type: ${recv.type}
Auth: ${plain.a}`);

		// Command
		if (recv.type === 'cmd') {
			console.log('CMD::' + recv.info);
			console.log(recv.payload);
			// Auth passed
			if (plain.a === true) {
				// Receive invitation
				if (recv.info === 'invitation') {
					ch_share = recv.payload;
					client_msg.subscribe(ch_share, function (err) {
						if (!err) {
							send_cmd(client, 'echo', ch_share, self_id_hash, self_id, self_pvk, ut.get_key(recv.sender, false));
							console.log(`${recv.sender} switched the channel to ${ch_share}`);
						} else {
							console.log('! Cannot listen on channel ' + ch_share);
						}
					});

				// Receive echo
				} else if (recv.info === 'echo') {
					client_msg.subscribe(ch_share, function (err) {
						if (!err) {
							console.log(`Channel is switched to ${ch_share}`);
						} else {
							console.log('! Cannot listen on channel ' + ch_share);
						}
					});
				} else {
					console.log('! Unsupported command');
				}
			// Auth failed
			} else {
				console.log('! Ignore invalid command');
			}
		// Not a command
		} else {
			console.log('! Private room only receives control commands');
		}
		console.log('===========================');
		return 0;
	});
	
	client_msg.on('message', function (ch, msg) {
		const sMsg = lz.decompressFromBase64(msg.toString());
		// Think how to decide opposite_pbk
		const plain = en2Plain(sMsg, self_pvk, ut.get_key(room_id, false));
		if (plain === -1) {
			// console.log('*** Unreadable message');
			return -1;
		}
		const recv = plain.r;
		console.log(`
===========================
NEW MESSAGE @ ${ch}
---------------------------
From: ${recv.sender}
Time: ${recv.time}
Type: ${recv.type}
Auth: ${plain.a}`);

		// Plain text
		if (recv.type === 'utf-8') {
			console.log('Contant:\n' + recv.payload);
		
		// Binary
		} else if (recv.type === 'hex') {
			console.log('Info: ' + recv.info);
			fs.writeFile('./fileRecv/' + recv.info, Buffer.from(recv.payload, 'hex'), function (err) {
				if (err) {
					throw err;
				} else {
					console.log(`File ${recv.info} is saved.`);
				}
			});
		}
		console.log('===========================');
		return 0;
	});

	this.send_plaintxt = function (plaintxt, opposite_pbk) {
		const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(self_id, plaintxt), self_pvk, opposite_pbk, 'utf-8');
		client_msg.publish(ch_share, msg);
		console.log(`Send ${msg.length} bytes.`);
	}

	this.send_plainbin = function (plainBin, opposite_pbk, ext) {
		const hash = hcp.sha(plainBin, 'md5');
		const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(self_id, plainBin, 'hex', hash+ext), self_pvk, opposite_pbk, 'utf-8');
		client_msg.publish(ch_share, msg);
		console.log(`Send ${msg.length} bytes.`);
	}
}

module.exports = HC;