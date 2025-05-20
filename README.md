# Experiment 6: Blockchain-Based Passwordless Authentication (Using Public-Private Key Cryptography)
# Aim:
To implement a secure passwordless authentication system using public-private key cryptography on Ethereum. This prevents phishing and password leaks.

# Algorithm:
Step 1: User Registration
A user registers with their Ethereum public key (instead of a password).


Step 2: Login Process
When logging in, the user signs a random challenge message using their private key.


The smart contract verifies the signature using the user’s public key.



# Program:
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PasswordlessAuthDemo {
    struct User {
        bool registered;
        address pubKey;
        bytes32 privateKey; // Fake private key for demo
    }

    mapping(address => User) public users;
    bytes32 public latestChallenge;

    event UserRegistered(address user, address pubKey, bytes32 privateKey);
    event ChallengeGenerated(bytes32 challenge);
    event SignatureGenerated(bytes32 hash, uint8 v, bytes32 r, bytes32 s);

    // Step 1: Register user
    function registerUser() public {
        require(!users[msg.sender].registered, "Already registered");

        // Fake public/private keys
        address fakePubKey = msg.sender;
        bytes32 fakePrivateKey = keccak256(abi.encodePacked(msg.sender, block.timestamp));

        users[msg.sender] = User({
            registered: true,
            pubKey: fakePubKey,
            privateKey: fakePrivateKey
        });

        emit UserRegistered(msg.sender, fakePubKey, fakePrivateKey);
    }

    // Step 2: Generate random challenge
    function generateChallenge() public returns (bytes32) {
        require(users[msg.sender].registered, "User not registered");
        latestChallenge = keccak256(abi.encodePacked(block.timestamp, msg.sender));
        emit ChallengeGenerated(latestChallenge);
        return latestChallenge;
    }

    // Step 3: "Sign" the challenge (fake signing)
    function generateSignature() public returns (bytes32 hash, uint8 v, bytes32 r, bytes32 s) {
        require(users[msg.sender].registered, "User not registered");
        
        hash = latestChallenge;
        bytes32 combined = keccak256(abi.encodePacked(users[msg.sender].privateKey, hash));
        
        // Fake values for r, s, v
        r = bytes32(uint256(uint160(users[msg.sender].pubKey)) << 96);
        s = combined;
        v = 27;

        emit SignatureGenerated(hash, v, r, s);

        return (hash, v, r, s);
    }

    // Step 4: Authenticate
    function authenticate(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        require(users[msg.sender].registered, "User not registered");

        bytes32 expectedCombined = keccak256(abi.encodePacked(users[msg.sender].privateKey, hash));
        bytes32 expectedR = bytes32(uint256(uint160(users[msg.sender].pubKey)) << 96);
        uint8 expectedV = 27;

        if (r == expectedR && s == expectedCombined && v == expectedV) {
            return true;
        } else {
            return false;
        }
    }
}
```

# Expected Output:
Users can register without a password.


Users sign a challenge with their private key for authentication.


The smart contract verifies signatures to confirm identity.



# High-Level Overview:
Eliminates password hacks & phishing attacks.


Uses Ethereum's built-in cryptographic functions.


Inspired by Web3 login solutions like MetaMask authentication.

# RESULT: 

![image](https://github.com/user-attachments/assets/9e26475a-1a74-49a8-bec0-389f2c9dba32)
![image](https://github.com/user-attachments/assets/3c1c7f94-2ef4-4311-95bc-d99bdad845c5)

![image](https://github.com/user-attachments/assets/b9fdbd73-c08b-448e-a179-ef6742fa26a9)
![image](https://github.com/user-attachments/assets/8633636b-f124-46b1-aa52-a9851e783616)

![image](https://github.com/user-attachments/assets/57a54669-c8b5-44a2-8fcd-e2602b64a843)
![image](https://github.com/user-attachments/assets/1d26faf7-ded8-44cd-8344-3cbc4a2c47dd)

![image](https://github.com/user-attachments/assets/7401e5ea-19ff-4695-abb8-fdf756a08d14)
![image](https://github.com/user-attachments/assets/4b49e592-6af7-45e1-b544-49e32b812178)

![image](https://github.com/user-attachments/assets/7cda7e7a-6475-4ff9-b3d6-5ac4badb133e)

![image](https://github.com/user-attachments/assets/ab14af59-5e7c-4852-8411-54c2742a6af0)

![image](https://github.com/user-attachments/assets/72b23add-4904-4da9-ad3a-33f2f543c572)
