# find-peers

  A module to find nodes on a network, using a multicast and a tcp server.
  
  ## Dependencies
  ```
  npm i ip
  npm i bcryptjs
  ```
  ## Installation  
  `npm i find-peers`
  ## Usage
   Import  
     ```
     const { setIdentity, findPeers, getPeerSet } = require('find-peers');
     ```
  
   Set the identity 
   Set the machine's IP, a random device name, and the name for the deployment application  
    ```
    setIdentity({ app: 'exampleApp'});
    ```
   
   Find peers  
    ```
    findPeers(MULTICAST_ADDRESS, MULTICAST_PORT, TCP_PORT, PASSCODE, SEARCH_TIME)
    findPeers('239.255.255.255', 15000, 15001, 'password', 10);
    ```
    
   Get list of peers  
    ```
    const peerSet = getPeerSet();
    ```
    
   ### Example usage:  
   ```
   const { setIdentity, findPeers, getPeerSet } = require('find-peers');
   setIdentity({ app: 'exampleApp'});
   findPeers('239.255.255.255', 15000, 15001, 'password', 10).then(() => {
     const peerSet = getPeerSet();
     for(let peer of peerSet) 
        console.log(`${peer.name} at ${peer.ip}`);
    });
   ```
