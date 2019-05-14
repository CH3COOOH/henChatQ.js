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

	var client = mqtt.connect(serv);
	var client_msg = mqtt.connect(serv);
	var ch_share = null;
	const self_id_hash = hcp.sha(self_id).slice(0, 32);
	const room_id_hash = hcp.sha(room_id).slice(0, 32);

	client.on('connect', function () {
		client.subscribe(room_id_hash, function (err) {
			if (!err) {
				console.log('Listing on channel ' + room_id_hash);
				console.log('Channel of self ' + self_id_hash);
				ch_share = crypto.randomBytes(32).toString('hex');
				send_cmd(client, 'invitation', ch_share, self_id_hash, self_id, self_pvk, ut.get_key(room_id, true));
			} else {
				console.log('! Cannot listen on channel ' + room_id_hash);
				client.end();
			}
		});
	});

	client.on('message', function (ch, msg) {
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
// send_cmd = function (type, content, ch_target, self_id, self_pvk, opposite_pbk)
		// Command
		if (recv.type === 'cmd') {
			console.log('CMD::' + recv.info);
			console.log(recv.payload);
			// Auth passed
			if (plain.a === true) {
				// Receive invitation
				if (recv.info === 'invitation') {
					ch_share = recv.payload;
					client_msg.subscribe(ch_share);
					send_cmd(client, 'echo', ch_share, self_id_hash, self_id, self_pvk, ut.get_key(recv.sender));
				// Receive echo
				} else if (recv.info === 'echo') {
					client_msg.subscribe(ch_share);
				}
			// Auth failed
			} else {
				console.log('Ignore invalid command');
			}
			
		// Plain text
		} else if (recv.type === 'utf-8') {
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
		const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(ch_share, plaintxt), self_pvk, opposite_pbk, 'utf-8');
		client.publish(self_id_hash, msg);
		console.log(`Send ${msg.length} bytes.`);
	}

	this.send_plainbin = function (plainBin, opposite_pbk, ext) {
		const hash = hcp.sha(plainBin, 'md5');
		const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(ch_share, plainBin, 'hex', hash+ext), self_pvk, opposite_pbk, 'utf-8');
		client.publish(self_id_hash, msg);
		console.log(`Send ${msg.length} bytes.`);
	}
}

module.exports = HC;