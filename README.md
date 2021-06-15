# A Secured Chat Application

## Purpose
This project has been done as part of required tasks in Network Security course (COE451) at KFUPM in Term 201. It is an improvement to an available [open-source chat application](https://github.com/sdht0/P2P-chat-application) that has no encryption. It implements SSH using low-level RSA and Diffie-Hellman to secure exchange of symmetric key. The messages are encrypted using AES256-CBC.

## Installation

You can use either pip or Anaconda to install the requirements. Note that the application is written in Python 2 language.

In pip from the tree directory:
```bash
pip install -r requirements.txt
```
or in Anaconda from the tree directory:
```bash
conda env create --file environment.yml
```

## Usage
From program file, use:
```bash
python chatApp_Alice.py
python chatApp_Bob.py
```

## Run examples

### Run Test
![Figure 1](/images/test0.png)
### Cypher Proof
![Figure 2](/images/test1.png)
### Case 1: Trudy posing as Bob
This case and below case are done by changing the private key of coresponding user.
![Figure 3](/images/test2.png)

### Case 2: Trudy posing as Alice
![Figure 4](/images/test2.png)
## Credit
- [Original Application](https://github.com/sdht0/P2P-chat-application)
- [RSA Helper Codes](https://www.geeksforgeeks.org)
## License
[MIT](https://choosealicense.com/licenses/mit/)