# Description
A secure electronic voting system that allows a user to register for voting, vote for a candidate, validate votes of a voter, and display and verify vote tally.

Includes support for confidentiality and integrity protection of messages exchanged between components and implements routines to read and write sensitive data like voter IDs and votes to an encrypted file.

Votes were stored in files as Merkle Trees which were encrypted using AES-128 and hashed using SHA-256.

# To Run the Program
`python3 votingsystem.py`

