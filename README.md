# henChatQ.js

**henChatQ.js** is a simplified communication application without a customized server. It is based on MQTT protocol, and can send/receive messages to/from any MQTT broker deployed on the Internet.

## Quick start
### CUI mode
1. Generate your key pair  
`node newUser.js`  
Two files will be generated: [yourid].key.pem and [yourid].pem. [yourid].pem is your public key, and you can share it with your friends, while you should **NEVER SEND THE [yourid].key.pem TO OTHERS**.
2. `node henChat-cui.js -u [yourid] -t [targetid]`  
Make sure that [targetid].pem is in the folder `./cards`. You may get it from your friends. By excuting the command upon, the session is established.
3. You will see `MSG>` in CUI. Just input what you want to say and press ENTER. If the message starts with "#", it will be seen as sending a file, and string after "#" should be the path.

### GUI mode
(Under developing...)
