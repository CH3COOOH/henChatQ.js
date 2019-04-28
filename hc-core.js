'use strict'

const fs = require('fs');
const mqtt = require('mqtt');
const lz = require('lz-string');
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

var HC = function (serv, self_id, room_id, self_pvk) {

	var client = mqtt.connect(serv);

	client.on('connect', function () {
		client.subscribe(room_id, function (err) {
			if (!err) {
				console.log('Listing on channel ' + room_id);
			} else {
				console.log('! Cannot listen on channel ' + room_id);
				client.end();
			}
		});
	});

	client.on('message', function (ch, msg) {
		const sMsg = lz.decompressFromUTF16(msg.toString());
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
		if (recv.type === 'utf-8') {
			console.log('Contant:\n' + recv.payload);
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
		client.publish(self_id, msg);
		console.log(`Send ${msg.length} bytes.`);
	}

	this.send_plainbin = function (plainBin, opposite_pbk, ext) {
		const hash = hcp.sha(plainBin, 'md5');
		const msg = hcp.gen_encryptedMsg(hcp.plainDataPackage(self_id, plainBin, 'hex', hash+ext), self_pvk, opposite_pbk, 'utf-8');
		client.publish(self_id, msg);
		console.log(`Send ${msg.length} bytes.`);
	}
}

module.exports = HC;