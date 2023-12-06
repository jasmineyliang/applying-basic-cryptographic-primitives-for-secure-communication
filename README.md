# applying-basic-cryptographic-primitives-for-secure-communication
Three Java programs, an AsymmetricKeyProducer, a Server and a Client.

The AsymmetricKeyProducer program can randomly generate a pair of RSA public and private keys. It should work as follows:
1. It runs with two arguments provided by its user:
  1) The file to store the public key; and
  2) The file to store the private key.
2. It randomly generates a pair of public and private keys each with 2048 bits.
3. It stores the keys to the user-provided files, respectively. (Refer to and feel free to reuse the example code in the appendix.)
The server and client programs simulate the interaction between a (highly simplified) secure cloud storage server and it client.
The Server program should work as follows:
1. The server runs with the following arguments:
  1) The Server’s port number;
  2) The pathname of a file containing the server’s private key;
  3) The pathname of a file containing the client’s public key.
    (Note: The private/public keys should be 2048-bit long.)
2. The server creates a socket and waits for the client to connect. Once the client connects, it interacts with the client in the following two rounds.
  a. In the first round, the server will receive from the client the following:
    i. a 256-bit AES key encrypted by the server’s public key, and
    ii. the client’s digital signature for the AES key.
In response, the server should:
    i. decrypt the AES key;
    ii. verify if the received client’s digital signature matches the key (and output if hey match or not);
    iii. generate its own digital signature for the key; and
    iv. send its digital signature to the client.
(Note: The digital signatures should be generated/verified based on the algorithm combination “SHA512withRSA”. The received AES key will be used as a symmetric key shared by the server and its client in the next round.)
b. In the second round, the server will receive from the client the following:
    i. size of a plaintext string (in the unit of byte);
    ii. an AES-encrypted version of the string (i.e., one or multiple blocks of ciphertext); and
    iii. a digital signature for the plaintext string produced by the client.
In response, the server should:
  i. use the shared AES key to decrypt the received ciphertext and output the plaintext;
  ii. check if the received client’s digital signature matches the plaintext, and output if they match;

