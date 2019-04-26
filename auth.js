'use strict';

const NodeRSA = require('node-rsa');
const program = require('commander');
const fs = require('fs');
const crypto = require('crypto');

function Auth () {

	this.sha = function (data, algo) {
		const hash = crypto.createHash(algo);
		hash.update(data);
		var hash_data = hash.digest('hex');
		return hash_data;
	}

	this.generate_key = function () {
		var key = new NodeRSA({b: 2048});
		key.setOptions({ encryptionScheme: 'pkcs1' });
		var privatePem = key.exportKey('pkcs1-private-pem');
		var publicPem = key.exportKey('pkcs1-public-pem');
		this.external_pvk = privatePem;
		this.external_pbk = publicPem;
		return {'pvk': privatePem, 'pbk': publicPem};
	}

	this.export_key = function (pbk, pvk, sname_pbk, sname_pvk) {
		fs.writeFile(sname_pbk, pbk, function (err) {
			if (err) throw err;
			console.log('Public key saved.');
		});
		fs.writeFile(sname_pvk, pvk, function (err) {
			if (err) throw err;
			console.log('Private key saved.');
		});
	}

	this.import_key = function (fname) {
		return fs.readFileSync(fname, 'binary');
	}

	this.encrypt = function (key_pkcs1, plain, enPrivate=false) {
		var key = new NodeRSA(key_pkcs1);
		if (enPrivate) {
			return key.encryptPrivate(plain, 'hex', 'hex');
		} else {
			return key.encrypt(plain, 'hex', 'hex');
		}
	}
	
	this.decrypt = function (key_pkcs1, msg, dePublic=false) {
		var key = new NodeRSA(key_pkcs1);
		if (dePublic) {
			return key.decryptPublic(msg, 'hex', 'hex');
		} else {
			return key.decrypt(msg, 'hex', 'hex');
		}
	}

	this.newUser = function () {
		const keypair = this.generate_key();
		const username = this.sha(crypto.randomBytes(32).toString('hex'), 'md5').slice(0,10);
		this.export_key(keypair['pbk'], keypair['pvk'], username+'.pem', username+'.key.pem');
	}
}

module.exports = Auth;


// var auth = new Auth();
// var keypair = auth.generate_key();
// program
// 	.version('0.0.1')
// 	.option('-u, --username [username]', 'Create a new user')
// 	.parse(process.argv);
// auth.export_key(keypair['pbk'], keypair['pvk'], program.username+'-pbk.pem', program.username+'-pvk.pem');
// auth.newUser();