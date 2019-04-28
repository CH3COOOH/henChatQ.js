const readline = require('readline');
const program = require('commander');
const fs = require('fs');
const path = require('path');

var Utilize = require('./utilize');
var HC = require('./hc-core');
var HCipher = require('./hcrypto.js');
var ut = new Utilize();

const msgServer = 'mqtt://henchat.ml';
const hcp = new HCipher();

program
	.version('0.0.1')
    .option('-u, --username [username]', 'Login as user input')
    .option('-t, --target [target]', 'Username of the target')
	.parse(process.argv);

var rl_chat = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

var     username    = program.username;
var     privateKey  = ut.get_key(username, true);
var     hc_room     = new HC(msgServer, username, program.target, privateKey);

rl_chat.setPrompt('MSG> ');
rl_chat.prompt();

rl_chat.on('line', function (line) {
    if (line[0] != '#') {
        hc_room.send_plaintxt(line, ut.get_key(program.target, false));
    } else {
        let fname = line.slice(1,);
        let bin = fs.readFileSync(fname, 'hex');
        hc_room.send_plainbin(
            bin,
            ut.get_key(program.target, false),
            hcp.sha(bin, 'md5') + path.extname(fname));
    }
    rl_chat.prompt();
});