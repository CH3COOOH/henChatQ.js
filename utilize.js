fs = require('fs');
const Auth = require('./auth.js');
const auth = new Auth();

function Utilize () {

    this.get_key = function (username, pvk=true) {
        var fname_kv = null;
        if (pvk) {
            fname_kv = username + '.key.pem';
        } else {
            fname_kv = './cards/' + username + '.pem';
        }
        // if (fs.readdirSync('./').indexOf(fname_kv) == -1) {
        //     console.log('Invalid username!');
        //     return -1;
        // }
        try {
            kv = auth.import_key(fname_kv);
        } catch (error) {
            console.log('! Cannot import key file ' + fname_kv);
            return -1;
        }
        return kv;
    }
}

module.exports = Utilize;