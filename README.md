# find-peers ![Visits](https://lambda.348575.xyz/repo-view-counter?repo=find-peers)

A module to find nodes on a network, establish secure communication channels, execute code and much much more.

## NOTE: v3.0 will depreciate http/s, socket.io, hashed key exchange.

## Features
- [ ] Communication channels after node discovery

- [ ] Node monitoring via a local web server
- [ ] Complete control over node & remote access terminals
- [ ] Scale and execute code on connected peers (Javascript through [Node.js VM](https://nodejs.org/api/vm.html) or binary executables through [Child Process](https://nodejs.org/api/child_process.html))
- [ ] File transfers & file synchronisation
- [ ] Sync with a node list on a server
- [x] Automatically refresh node status every N seconds
- [ ] Interact through emitted events, RXJS or promises
- [x] Communication through TCP, HTTP, TLS, HTTPS or socket.io
- [ ] Definable master-slave sub networks / nodes
- [ ] 6 Authentication levels:
- [x] No authentication (0)
- [x] Hashed key exchange (1)
- [x] Encrypted key (2)
- [x] Generated key exchange (RSA, ec, x448) etc. (3)
- [x] End to end encryption (4)
- [ ] Middle man server communication (5)
## Installation  
```
npm i find-peers --save
```

## Installation notes
#### Socket.io
To use find-peers in [Socket.io](https://socket.io/) mode install it first.
```
npm i socket.io-client
npm i socket.io
``` 
#### node-forge
To automatically generate self signed SSL certificates at runtime [node-forge](https://www.npmjs.com/package/node-forge) must be installed.
```
npm i node-forge
```
## Quick usage
#### Import it
```js
const { FindPeers } = require('find-peers');
```

#### Basic config
```js
const options = { autoGenId: true };
```
#### Create instance
```js
const find = new FindPeers(options);
```
#### Listen for events
```js
  find.on('found-nodes', (data) => {
      // new discovered nodes
  });
  find.on('server_up', () => {
      console.log('server is up!');
  });
  find.on('server_err', (err) => {
      console.log(err);
  });
  find.on('multicast_err', (err) => {
      console.log(err);
  });
  find.on('echo', (data) => {
      console.log(data.message, 'from', data.from.id);
  });
```

## Config options
| Property              	| Description                                                                                                                                                                      	| Default value                                                                                                                                                                                                                                                                                                                                          	|
|-----------------------	|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
| autoGenId             	| Automatically generate a 32 word random id                                                                                                                                       	| false                                                                                                                                                                                                                                                                                                                                                  	|
| identity              	| Set node details: id, bind to ip etc.                                                                                                                                            	| undefined                                                                                                                                                                                                                                                                                                                                              	|
| securityLevel         	| Security mode of the library to be used                                                                                                                                          	| 4                                                                                                                                                                                                                                                                                                                                                      	|
| verifyTries           	| Number of times to attempt to verify a node during initial pairing                                                                                                               	| 3                                                                                                                                                                                                                                                                                                                                                      	|
| tryTime               	| Timeout limit                                                                                                                                                                    	| 10000                                                                                                                                                                                                                                                                                                                                                  	|
| hashOptions           	| Options passed to argon 2 as per argon2.Options from [node-argon2](https://github.com/ranisalt/node-argon2) ( 1 )                                                                	| <pre>{ hashLength: 32, memoryCost: 2**16, parallelism: 1, type: argon2.argon2i }</pre>                                                                                                                                                                                                                                                                            	|
| modLength             	| Length of generated RSA key ( 3 )                                                                                                                                                	| 2048                                                                                                                                                                                                                                                                                                                                                   	|
| keyGenGroup           	| Algorithm for key generation ( 3 )                                                                                                                                               	| rsa                                                                                                                                                                                                                                                                                                                                                    	|
| aesVersion            	| Type of aes-256 to be used ( 2 - 4 )                                                                                                                                             	| aes-256-cbc                                                                                                                                                                                                                                                                                                                                            	|
| oaepHash              	| Hash to use alongside pbkdf2                                                                                                                                                     	| sha-256                                                                                                                                                                                                                                                                                                                                                	|
| groupName             	| Mod group to use in Diffie - Hellman exchange                                                                                                                                    	| modp15                                                                                                                                                                                                                                                                                                                                                 	|
| autoStartSearch       	| Automatically start searching for nodes as soon as object is created                                                                                                             	| true                                                                                                                                                                                                                                                                                                                                                   	|
| serverType            	| Server type to be used for communication after node discovery                                                                                                                    	| tcp                                                                                                                                                                                                                                                                                                                                                    	|
| serverPort            	| Server port                                                                                                                                                                      	| 19235                                                                                                                                                                                                                                                                                                                                                  	|
| multicastPort         	| Multicast port                                                                                                                                                                   	| 18235                                                                                                                                                                                                                                                                                                                                                  	|
| broadCastInterval     	| Interval at which to send out multicast                                                                                                                                          	| 500                                                                                                                                                                                                                                                                                                                                                    	|
| multiCastTimeout      	| Duration of node search                                                                                                                                                          	| 60000                                                                                                                                                                                                                                                                                                                                                  	|
| multiCastReSearch     	| Automatically re - search for nodes                                                                                                                                              	| 300000                                                                                                                                                                                                                                                                                                                                                 	|
| shouldReSearch        	| Enable re - search                                                                                                                                                               	| false                                                                                                                                                                                                                                                                                                                                                  	|
| searchForever         	| Disable multiCastTimeout and re - search                                                                                                                                         	| false                                                                                                                                                                                                                                                                                                                                                  	|
| shouldPing            	| Ping nodes to veriy if still active                                                                                                                                              	| false                                                                                                                                                                                                                                                                                                                                                  	|
| pingInterval          	| Interval to ping nodes at                                                                                                                                                        	| 1000                                                                                                                                                                                                                                                                                                                                                   	|
| pingCount             	| Number of failed ping attempts before marked as disconnect                                                                                                                       	| 20                                                                                                                                                                                                                                                                                                                                                     	|
| temporaryDisconnect   	| Number of failed ping attempts before marked as temporary disconnect                                                                                                             	| 10                                                                                                                                                                                                                                                                                                                                                     	|
| pingMIA               	| Number of seconds between ping reponses to be marked as temporary disconnect                                                                                                     	| 25000                                                                                                                                                                                                                                                                                                                                                  	|
| pingLimit             	| Number of failed ping attempts before reconnection attempts are stopped                                                                                                          	| 100                                                                                                                                                                                                                                                                                                                                                    	|
| whiteList             	| Array of nodes (by ip or id) to be whitelisted from ping                                                                                                                         	| undefined                                                                                                                                                                                                                                                                                                                                              	|
| blackList             	| Array of nodes (by ip or id) to be blacklisted from connections                                                                                                                  	| undefined                                                                                                                                                                                                                                                                                                                                              	|
| privateServerKey      	| Private key for https, tls server or Socket.io https server                                                                                                                      	| undefined                                                                                                                                                                                                                                                                                                                                              	|
| certificate           	| Certificate / public key for https, tls server or Socket.io https server                                                                                                         	| undefined                                                                                                                                                                                                                                                                                                                                              	|
| genKeypair            	| Automatically generate an SSL key pair (private key, certificate) for use with https, tls or Socket.io https server using [node-forge](https://www.npmjs.com/package/node-forge) 	| false                                                                                                                                                                                                                                                                                                                                                  	|
| attrs                 	| Attributes passed for SSL key pair generation (country name, address, organization name, etc...)                                                                                 	| <pre> [{ name :  'commonName' ,  value :  'example.org' } ,  <br>{ name :  'countryName' ,  value :  'US' } ,       <br>{ shortName :  'ST' ,  value :  'Virginia' } ,       <br>{ name :  'localityName' ,  value :  'Blacksburg' } ,       <br>{ name :  'organizationName' ,  value :  'Test' } ,       <br>{ shortName :  'OU' ,  value :  'Test' }] </pre> 	|
| socketIOOptions       	| Options to be used with Socket.io server                                                                                                                                         	| <pre> { path:'/', mode:'http' } </pre>                                                                                                                                                                                                                                                                                             	|

## Functions

| Function      	| Description                         	| Arguments                         	|
|---------------	|-------------------------------------	|-----------------------------------	|
| getClients    	| Get entire list of verified nodes   	| void                              	|
| echo          	| Send a message to all nodes         	| message: string, omit ?: string[] 	|
| messageClient 	| Send message to a specific node     	| id: string, message: string       	|
| getIdentity   	| Get identity object of current node 	| void                              	|
