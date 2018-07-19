dt-----
Vanitygen ETH!  
-----
  
**Download the latest binary from: https://github.com/kjx98/vanitygen-eth/releases !**  

Forked from exploitagency/vanitygen-plus ,  
then modified by Jesse Kuang
to support ETH-Token and ERC20 Tokens,  
and with the following changes:  
  
 + upgrade support for openssl 1.1+
  
**WARNING!** This program has not been thoroughly tested.  Please attempt importing an address first.  
Send a tiny amount you don't mind losing to the address.  Then perform a test spend.  
I will not be held liable for lost funds as a result of the use of this program.  
Also do not use this program for nefarious purposes!  I do not condone illegal activity.  
The chances of actually brute forcing an address is nearly impossible anyways.  
  
Be sure to report any issues or bugs and fixes, I am happy to accept pull requests!  
If you have an altcoin you would like to add please let me know.  

-----
Getting Started  
-----  
**Download the latest binary from: https://github.com/kjx98/vanitygen-eth/releases !**  
Linux Binary (Compiled on 64bit Debian 18.04 Testing)
Windows Binary (Compiled on Win10 64bit), not yet
  
Extract the files, 
open a terminal/command prompt,  
change to directory containing vanitygen-EOS binaries.  
  
Running On Linux: `./vanity -ARGS`, or , `./keyconv -ARGS`, etc  
Running On Windows: `vanity.exe -ARGS`, `keyconv.exe -ARGS`, etc  
  
**For generating addresses using the CPU(slower) use: vanity !**  
**For generating addresses using the GPU(faster) use: oclvanity !**  
  
**NOTES:**	All arguments are case sensitive!  
	Address prefix must be at the end of the command.  
	oclvanitygen requires OpenCL and correct drivers.  
  
Example output of above command:  
>Generating ETH Address  
>Difficulty: 65536
>Pattern: 518a                                                                  
>Address: 0x518a7f9ae5bb72e34e8bcd25f6912199169ccfa0
>Privkey: 0x17c71c86be6aef0db73b98357cba6679e598f882d46df79c1e53803a3b50e588
  
-----
  
**If you found this repo useful, please consider a donation.  Thank You!**  
  
 * Donate Bitcoin: 189182eexobQMBp7uXDQWWhUC2ptT1jWfU
 * Donate LTCcoin: LiVeShML2LEHBkRmjuiRBCUgEhtRdEtSst
 * Donate Ethereum or Ethereum Classic: 0x9672500b5355f410ecb01d1c4fe26e24acdc068c
 * Donate Monero: 49K25rZnQW6N3HaBDpPbq2DvbV8fezafaVCom5LkZNGqhLRFpHPVNyJbror58tBXejWPq5iy3EqU255MxnymRSsnKAbY8Aw
 * Donate EOS: EOS8fhYH8Jt5gy9DJffMZBgB5BvDt9cDfTaSpkEkHmRqEy88eLWK8
