'use strict'

const crypto = require('crypto');
const lz = require('lz-string');
const Auth = require('./auth.js');
const auth = new Auth();
const ALGO_AES = 'aes-256-ctr';
const ALGO_HASH = 'sha256';

function HCipher () {
	this.sha = function (data, algo=ALGO_HASH) {
		const hash = crypto.createHash(algo);
		hash.update(data);
		var hash_data = hash.digest('hex');
		return hash_data;
	}

	this.aes = function (data_buf, encode='utf-8') {
		const password = crypto.randomBytes(32).toString('hex');
		const key = crypto.scryptSync(password, 'salt', 32);
		const iv = Buffer.alloc(16, 0);
		const cipher = crypto.createCipheriv(ALGO_AES, key, iv);
		let encrypted = cipher.update(data_buf.toString(encode), encode, 'hex');
		encrypted += cipher.final('hex');
		return {'en': encrypted, 'k': key};
	}

	this.aes_de = function (data_hex, k, encode='utf-8') {
		const decipher = crypto.createDecipheriv(ALGO_AES, k, Buffer.alloc(16, 0));
		let decrypted = decipher.update(data_hex, 'hex', encode);
		decrypted += decipher.final(encode);
		return decrypted;
	}

	this.gen_encryptedMsg = function (plainData, pvk_0, pbk_1, d_type='utf-8') {
		const buf = Buffer.from(plainData, d_type);
		const aesed = this.aes(buf, d_type);
		const k = aesed.k;
		const mx = aesed.en;
		const hmx = this.sha(mx);

		const kr = auth.encrypt(pbk_1, k);
		const hmxr = auth.encrypt(pvk_0, hmx, true);

		return lz.compressToUTF16(hmxr + kr + mx);
		// return hmxr + kr + mx;
	}

	// Structure of message:
	// +----------+--------+---------+
	// |header_len| header | payload |
	// |    2     |   ?    |    ?    |
	// +----------+--------+---------+
	//           /          \
	// +-----------+-----------+------+------------+
	// | sender_id | timestamp | type | additional |
	// +-----------+-----------+------+------------+
	this.plainDataPackage = function (sender, plainData, d_type='utf-8', additional=null) {
		var header = `${sender}\x99${new Date().getTime()}\x99${d_type}\x99${additional}`
		const len = header.length;
		if (len > 255) {
			header = header.slice(0, 255);
		}
		var sLen = len.toString(16);
		if (sLen.length < 2) {
			sLen = '0' + sLen;
		}
		return sLen + header + plainData;
	}

	this.verify = function (hmxr, hmx_local, sender, keybook) {
		const opposite_kb = keybook[sender];
		const hmx_recv = Buffer.from(auth.decrypt(opposite_kb, hmxr, true), 'hex');
		if (hmx_recv.toString('hex') === hmx_local) {
			return true;
		} else {
			return false;
		}
	}

	this.dec_encryptedMsg = function (recvData, pvk_1, pbk_0, d_type='utf-8') {
		const hmxr = Buffer.from(recvData.slice(0, 512), 'hex');
		const kr = Buffer.from(recvData.slice(512, 1024), 'hex');
		const mx = Buffer.from(recvData.slice(1024,), 'hex');

		const k = Buffer.from(auth.decrypt(pvk_1, kr), 'hex');
		const m = this.aes_de(mx, k, d_type);
		let hmx_recv = [-1];

		try {
			hmx_recv = Buffer.from(auth.decrypt(pbk_0, hmxr, true), 'hex');
		} catch (error) {
			console.log('*** Cannot verify the signature!');
			return {'m': m, 'auth': false};
		}
		
		const hmx_local = this.sha(mx.toString('hex'));

		if (hmx_recv.toString('hex') === hmx_local) {
			return {'m': m, 'auth': true};
		} else {
			return {'m': m, 'auth': false};
		}
	}

	this.extractRecv = function (plainDataRecv) {
		const len_h = parseInt(plainDataRecv.slice(0, 2), 16);
		var header = plainDataRecv.slice(2, 2+len_h);
		var header = header.split('\x99');
		const data = plainDataRecv.slice(2+len_h,);
		return {'sender': header[0],
				'time': parseInt(header[1]),
				'type': header[2],
				'info': header[3],
				'payload': data};
	}
}

module.exports = HCipher;

// console.log(`===== TEST OF PLAIN TEXT =====`);
// const t = 'テストメッセージ';
// const cp = new HCipher();

// const kb0 = auth.import_key('./a-pbk.pem').toString('binary');
// const kv0 = auth.import_key('./a-pvk.pem').toString('binary');
// const kb1 = auth.import_key('./b-pbk.pem').toString('binary');
// const kv1 = auth.import_key('./b-pvk.pem').toString('binary');

// const msg = cp.gen_encryptedMsg(cp.plainDataPackage(t), kv0, kb1, 'utf-8');

// const plain = cp.dec_encryptedMsg(msg, kv1, kb0);
// const recv = cp.extractRecv(plain.m);
// console.log(recv.time);
// console.log(recv.type);
// console.log(recv.info);
// console.log(`DECRYPTED: ${recv.payload}\nVERIFY: ${plain.auth}`);


// console.log(`\n===== TEST OF BINARY =====`);
// const fs = require('fs');
// const bin = fs.readFileSync('./favicon.ico', 'hex');
// const msgbin = cp.gen_encryptedMsg(cp.plainDataPackage(bin, 'hex', 'favicon_recv.ico'), kv0, kb1, 'utf-8');
// const plainbin = cp.dec_encryptedMsg(msgbin, kv1, kb0);
// // console.log(`DECRYPTED: ${plainbin.m}\nVERIFY: ${plainbin.auth}`);
// const recvBin = cp.extractRecv(plainbin.m);
// console.log(recvBin.time);
// console.log(recvBin.type);
// console.log(recvBin.info);
// // console.log(recv.data);
// fs.writeFile(recvBin.info, Buffer.from(recvBin.payload, 'hex'), function (err) {
// 	if (err) {
// 		throw err;
// 	}
// });