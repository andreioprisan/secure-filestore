# cstore

COMS W4181 - HW1 - cstore secure archive
Author: Andrei Oprisan <ao2775@columbia.edu>


Archive design:
1. files counter
2. files 1...n headers
3. files 1...n contents
4. hmac

cstore implementation utilizes AES CBC with PKCS7 for padding contents to a block size of 16.
The pseudorandom number generator at /dev/random is used with a 10k iteration SHA-256 as the key for file encryption. HMAC values are regenerated on add and delete actions based on user archive and password values.

To build the app, run
`make`

To clean up the build, run
`make clean`

