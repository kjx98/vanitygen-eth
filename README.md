-----
Vanitygen EOS!  
-----
  
**Download the latest binary from: https://github.com/kjx98/vanitygen-EOS/releases !**  

Forked from exploitagency/vanitygen-plus ,  
then modified by Jesse Kuang
to support various EOS-Token,  
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
**Download the latest binary from: https://github.com/kjx98/vanitygen-EOS/releases !**  
Linux Binary (Compiled on 64bit Debian 18.04 Testing)
Windows Binary (Compiled on Win10 64bit), not yet
  
Extract the files, 
open a terminal/command prompt,  
change to directory containing vanitygen-EOS binaries.  
  
Running On Linux: `./vanitygen -ARGS`, or , `./keyconv -ARGS`, etc  
Running On Windows: `vanitygen.exe -ARGS`, `keyconv.exe -ARGS`, etc  
  
**For generating addresses using the CPU(slower) use: vanitygen !**  
**For generating addresses using the GPU(faster) use: oclvanitygen !**  
  
**NOTES:**	All arguments are case sensitive!  
	Address prefix must be at the end of the command.  
	oclvanitygen requires OpenCL and correct drivers.  
  
Example output of above command:  
>Generating EOS Address  
>Difficulty: 379272
>EOS Pattern: 518a                                                              
>EOS Address: EOS518aMZ4X4Z7gxdSVmygP8hTHz5VwwezMHiLWxHnLRxJT9jztrF
>EOS Privkey: 5KMMK9Eu1P5RnEdfF1UFMJUFWio7b1EEyjZyk9mGyNGnUixsAUs
  
-----
Encrypting and Decrypting a vanitygen or oclvanitygen private key  
-----  
**Encrypting generated private key:**  
Linux: `./vanitygen -E password  5a`  
Windows: `./vanitygen -E password 5a`  
*For GPU use "oclvanitygen" in place of "vanitygen"*  

 * `5a` Choose address prefix "Aa"  
 * `-E password` Encrypt key with password as "password",  
**NOTE:** It is more secure to use option `-e` with no trailing password,  
then vanitygen prompts for a password so theres no command history.  
Also please choose a stronger password than "password".  
  
>Generating EOS Address  
>Difficulty: 112
>EOS Pattern: 5a                                                                
>EOS Address: EOS5aJkYcB4FVtEKaQrpxGbyJss1dXWfdboAXTRNutc3MsnPa6RFf
>EOS Protkey: PsWohuHuhj5FV3Z1uz9vJgapV86XtNQSJyZYrSSF4VxrX2wkWrSQysJ5rHgkapMWxx6f
  
**Decrypting generated ProtKey with Keyconv:**  
Linux: `./keyconv -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  
Windows: `keyconv.exe -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge`  
  
 * `-d` means decrypt the protected key of "yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge"  

>Enter import password:  --- Enter "password" or whatever you specified as password and press enter  
>Address: EOS5aJkYcB4FVtEKaQrpxGbyJss1dXWfdboAXTRNutc3MsnPa6RFf
>Privkey: 5Jg5iMo64KDzyaRkJ3tLZVMbch7NTh8CG89qJveaAMFYrxBfqgh
  
**If you found this repo useful, please consider a donation.  Thank You!**  
  
 * Donate Bitcoin: 189182eexobQMBp7uXDQWWhUC2ptT1jWfU
 * Donate LTCcoin: LiVeShML2LEHBkRmjuiRBCUgEhtRdEtSst
 * Donate Ethereum or Ethereum Classic: 0x9672500b5355f410ecb01d1c4fe26e24acdc068c
 * Donate Monero: 49K25rZnQW6N3HaBDpPbq2DvbV8fezafaVCom5LkZNGqhLRFpHPVNyJbror58tBXejWPq5iy3EqU255MxnymRSsnKAbY8Aw
 * Donate EOS: EOS8fhYH8Jt5gy9DJffMZBgB5BvDt9cDfTaSpkEkHmRqEy88eLWK8
