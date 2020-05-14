# Description
A secure electronic voting system that allows a user to register for voting, vote for a candidate, validate votes of a voter, and display and verify vote tally.

Includes support for confidentiality and integrity protection of messages exchanged between components and implements routines to read and write sensitive data like voter IDs and votes to an encrypted file.

The program creates the following data structures to store votes, vote tallies, and voter ids securely:
1. Voter ID dictionary: Keeps track of the voter IDs of all registered users
2. Votes dictionary: Keeps track of all the votes cast. The key is the candidate and its value are a list of all the voter ids of the voters that have cast their vote to that candidate
3. Merkle tree: A merkle tree file is created for each candidate and keeps track of all the votes cast for that candidate. Therefore, the number of merkle trees = number of candidates

The program consists of the following components:
1. Menu providing options to the user to choose a particular action. There are 6 options provided to the user:
2. Register voter: It will request the user for an identification number unique to the user which no one other than the user knows. Then it will check if the voter is already registered. If already registered, it requests the user to select the other options. Else, it calls the register function passing the unique ID. In the register function, the voter ID is generated which in this case is the hash of the unique id. The voter ID is also stored in a voter ID dictionary where the key is the unique ID and value is the corresponding voter ID. This voter ID is then returned to the user.
3. Vote: The program asks the user for the voter ID. It then checks if the voter ID is valid by checking the voter ID dictionary. It also checks if the user has already voted by querying the vote dictionary which keeps track of the votes given to the dictionary. If these two conditions are not satisfied, it means the voter is voting for the first time and the program then prompts the user to choose the candidate. Once a valid candidate is chosen, a vote function is called passing the voter ID and candidate. The function creates a merkle tree using the voter ID passed and stores in that candidate’s merkle tree file.
4. Validate votes: The program can validate the vote of a voter and return the voting trail. The voter id of the user is requested which is then sent to the validate function. The validate function first fetches the candidate to whom the vote was cast, decrypts the corresponding merkle tree file, and stores the tree in a dictionary. The dictionary is then iterated to check if the voter ID is present in the dictionary and stores the hashes of all the tree nodes traversed in a list. This list serves as the voting trail and is returned to the user.
5. Display vote tally: The program displays the votes cast for each candidate using the votes dictionary
6. Verify vote tally: The program requests the candidate number for whom the vote tally must be verified and calls the printMerkleTree with this candidate number. The function fetches the merkle tree of that candidate, decrypts, and prints it in a user-friendly manner.

Confidentiality is guaranteed by using AES-128 for encryption and decryption of the local files generated and integrity is guaranteed by using base64 encoding and SHA256 hashes.

# To Run the Program
`python3 votingsystem.py`

# External Modules used
1. AES module from pycryptodome library: Used for generating the AES 128 cipher to encrypt and decrypt the above data structures stored    in separate files (https://pypi.org/project/pycryptodome/)
2. Random module from pycryptodome: Use to generate random numbers for generating keys and IVs for AES 128 cipher.
3. Hashlib: For generating SHA-256 hashes used for creating the unique voter ID and building the merkle tree
4. Binascii and base64: For bas64 encoding and decoding of the above data structures after they have been encrypted to make it easy for    decryption.

# Screenshots
Registering voter with unique identification number 123, vote for candidate 1 and display vote tally
![Screenshot 1](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-1.png)

Registering voter with unique identification number 345, vote for candidate 2 and display vote tally
![Screenshot 2](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-2.png)

Display vote trails and vote tally audits for users with unique identification numbers 123 and 345
![Screenshot 3](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-3.png)

Register another user with a unique identification number as 456, vote for candidate 1, display vote tally and vote tally audit for candidate 1
![Screenshot 4](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-4.png)

Display vote trail for the user with a unique identification number 456
![Screenshot 5](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-5.png)

Error messages when registering an already registered user, voting for invalid voter ID and a voter voting again
![Screenshot 6](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-6.png)

Detection of modification of votes files when vote tally is displayed. This serves as an integrity check.
![Screenshot 7](https://github.com/droid76/Secure-Electronic-Voting-System/blob/master/Screenshots/Screenshot-7.png)
