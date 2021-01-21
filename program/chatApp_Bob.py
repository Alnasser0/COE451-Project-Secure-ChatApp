#import the needed libraries
from Tkinter import *
from ttk import *
import socket
import thread
from os import urandom
from Crypto.Cipher import AES
from hashlib import sha256
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import binascii
import secrets 
import RSA_Bob_py2 as RSA_Bob
from hashlib import sha256
from builtins import int, pow

message1_rec = False
message3_rec = False

#This class will handle the complete program
class ChatClient(Frame):
  
  #This function will initialize and handle the object variables
  def __init__(self, root):
    Frame.__init__(self, root)
    self.root = root
    self.initUI()
    self.serverSoc = None
    self.serverStatus = 0
    self.allClients = {}
    self.counter = 0
    
    #CryptoCypher stuff - same as Phase 2, but initlization key is securely random now before hashing
    ####################################################
    ####################################################
    self.Student_ID = urandom(16)
    self.hashed_key = sha256()
    self.blockSize = 16 #block size for AES
    self.buffsize = self.blockSize*8 #buffer size // message size
    self.hashed_key.update(self.Student_ID) #hash id
    self.hashed_key = self.hashed_key.digest() #hashed in binary
    self.iv = urandom(16) #a secure random IV.

    #Define DIFFIE-HELLMAN variables here
    #KNOWN TO BOTH - m has been converted to int using the below links
    #m=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    #https://www.convzone.com/hex-to-decimal/
    #https://www.mathsisfun.com/binary-decimal-hexadecimal-converter.html
    self.m=int(32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559)
    self.g = int(2)

    #Known to Bob
    self.H_Bob = int(0)

    #Functions to send and recieve encrypted messages
    ####################################################
    ####################################################
  def Encryption(self, Message, Key, iv): #encryption function. it will be used to encrypt sent messages
      encryptor = AES.new(Key, AES.MODE_CBC, iv) #Encryptor object of AES
      encrypted_text = encryptor.encrypt(pad(Message.encode(u'utf-8'), self.blockSize))
      self.iv = encrypted_text #set cipher to be the iv of next message for chaining.
      cypther = b64encode(iv + encrypted_text).decode(u'utf-8') #Cypher to be sent.
      print "\nIV/Chain of encypted message:"
      print binascii.hexlify(bytearray(iv)) 
      print "\nEncrypted Message (Cipher):"
      print binascii.hexlify(bytearray(encrypted_text)) 
      return cypther #returns encrypted message (the old iv and cypher)
  
  def Encryption_Byte(self, Message, Key, iv): #encryption function for bytes, used for SSH protocol
      encryptor = AES.new(Key, AES.MODE_CBC, iv) #Encryptor object of AES
      encrypted_text = encryptor.encrypt(pad(Message, self.blockSize))
      cypther = b64encode(iv + encrypted_text).decode(u'utf-8') #Cypher to be sent.
      return cypther #returns encrypted message (the old iv and cypher)


  def Decryption(self, Cipher, Key): #decryption function of recieved messages
      ct = b64decode(Cipher) #decode the encryption
      iv = ct[:16] #get iv of the message
      rev_obj = AES.new(Key, AES.MODE_CBC, iv) #create decoder of AES object.
      self.iv = ct[16:] #set iv to be the recived part of encrypted message for chaining
      print "\nRecieved IV/Chain:"
      print binascii.hexlify(bytearray(iv))
      print "\nRecieved Encrypted Message (Cipher):"
      print binascii.hexlify(bytearray(self.iv))
      return unpad(rev_obj.decrypt(ct[16:]), self.blockSize).decode(u"utf-8") #return plaintext.

  def Decryption_Byte(self, Cipher, Key): #decryption function for bytes, used for SSH protocol
      ct = b64decode(Cipher) #decode the encryption
      iv = ct[:16] #get iv of the message
      rev_obj = AES.new(Key, AES.MODE_CBC, iv) #create decoder of AES object.
      return unpad(rev_obj.decrypt(ct[16:]), self.blockSize) #return plaintext.

  ####################################################
  ####################################################


  #SSH Protocol implemented as functions below:
  ############################
  def Bob_Step_2(self, Alice_IP, Bob_IP, Alice_message):
      b = secrets.randbits(2048)
      Rb = int(secrets.randbits(256)).to_bytes(32, byteorder=u'big')
      Gb = int(pow(self.g,b,self.m)).to_bytes(256, byteorder=u'big')
      Alice = Alice_IP.encode()
      Bob = Bob_IP.encode()
      Ra = Alice_message[:32]
      Ga = Alice_message[32:]
      Ga_int = int.from_bytes(Ga, byteorder=u'big')
      Gab = int(pow(Ga_int,b,self.m)).to_bytes(256, byteorder=u'big')
      Concat_H = Alice+Bob+Ra+Rb+Ga+Gb+Gab
      hashed_key = sha256()
      hashed_key.update(Concat_H)
      self.H_Bob = hashed_key.digest()
      Decrypted_Sb = self.H_Bob+Bob
      Decrypted_Sb_int = int.from_bytes(Decrypted_Sb, byteorder=u'big')
      Sb_int_Sign = pow(Decrypted_Sb_int,RSA_Bob.dBob,RSA_Bob.nBob)
      Sb = int(Sb_int_Sign).to_bytes(512, byteorder=u'big')
      message2 = Rb+Gb+Sb
      print "\n b = "
      print b
      del b
      print "\n Ra (in byte) = "
      print Ra
      print "\n Rb (in byte )= "
      print Rb
      hashed_key = sha256()
      hashed_key.update(Gab)
      self.hashed_key=hashed_key.digest()
      print "\nBob new hashed key"
      print binascii.hexlify(bytearray(self.hashed_key)) 
      return message2


  ####################################################
  def Bob_Step_4(self, Alice_IP, Alice_message):
      #Bob computes Alice H and compares it to his own. Return signal if true or false
      #Fix message
      message = self.Decryption_Byte(Alice_message, self.hashed_key)
      Alice_Address_Length = len(Alice_IP)
      Sa = message[Alice_Address_Length:]
      Sa_int = int.from_bytes(Sa, byteorder=u'big')
      Decrypted_Sa_int = pow(Sa_int, RSA_Bob.eAlice, RSA_Bob.nAlice)
      Decrypted_Sa = int(Decrypted_Sa_int).to_bytes(512+Alice_Address_Length, byteorder=u'big')
      H = Decrypted_Sa[512-32:512]
      return self.H_Bob==H
  
  ####################################################
  ####################################################
  ####################################################

  #This function will handle the UI components 
  def initUI(self):
    self.root.title("Simple P2P Chat Client - Bob")
    ScreenSizeX = self.root.winfo_screenwidth()
    ScreenSizeY = self.root.winfo_screenheight()
    self.FrameSizeX  = 800
    self.FrameSizeY  = 600
    FramePosX   = (ScreenSizeX - self.FrameSizeX)/2
    FramePosY   = (ScreenSizeY - self.FrameSizeY)/2
    self.root.geometry("%sx%s+%s+%s" % (self.FrameSizeX,self.FrameSizeY,FramePosX,FramePosY))
    self.root.resizable(width=False, height=False)
    
    padX = 10
    padY = 10
    parentFrame = Frame(self.root)
    parentFrame.grid(padx=padX, pady=padY, stick=E+W+N+S)
    
    ipGroup = Frame(parentFrame)
    serverLabel = Label(ipGroup, text="Set: ")
    self.nameVar = StringVar()
    self.nameVar.set("SDH")
    nameField = Entry(ipGroup, width=10, textvariable=self.nameVar)
    self.serverIPVar = StringVar()
    self.serverIPVar.set("127.0.0.1")
    serverIPField = Entry(ipGroup, width=15, textvariable=self.serverIPVar)
    self.serverPortVar = StringVar()
    self.serverPortVar.set("8090")
    serverPortField = Entry(ipGroup, width=5, textvariable=self.serverPortVar)
    serverSetButton = Button(ipGroup, text="Set", width=10, command=self.handleSetServer)
    addClientLabel = Label(ipGroup, text="Add friend: ")
    self.clientIPVar = StringVar()
    self.clientIPVar.set("127.0.0.1")
    clientIPField = Entry(ipGroup, width=15, textvariable=self.clientIPVar)
    self.clientPortVar = StringVar()
    self.clientPortVar.set("8091")
    clientPortField = Entry(ipGroup, width=5, textvariable=self.clientPortVar)
    clientSetButton = Button(ipGroup, text="Add", width=10, command=self.handleAddClient)
    serverLabel.grid(row=0, column=0)
    nameField.grid(row=0, column=1)
    serverIPField.grid(row=0, column=2)
    serverPortField.grid(row=0, column=3)
    serverSetButton.grid(row=0, column=4, padx=5)
    addClientLabel.grid(row=0, column=5)
    clientIPField.grid(row=0, column=6)
    clientPortField.grid(row=0, column=7)
    clientSetButton.grid(row=0, column=8, padx=5)
    
    readChatGroup = Frame(parentFrame)
    self.receivedChats = Text(readChatGroup, bg="white", width=60, height=30, state=DISABLED)
    self.friends = Listbox(readChatGroup, bg="white", width=30, height=30)
    self.receivedChats.grid(row=0, column=0, sticky=W+N+S, padx = (0,10))
    self.friends.grid(row=0, column=1, sticky=E+N+S)

    writeChatGroup = Frame(parentFrame)
    self.chatVar = StringVar()
    self.chatField = Entry(writeChatGroup, width=80, textvariable=self.chatVar)
    sendChatButton = Button(writeChatGroup, text="Send", width=10, command=self.handleSendChat)
    TerminateChatButton = Button(writeChatGroup, text="Terminate", width=10, command=self.handleTerminateChat)
    self.chatField.grid(row=0, column=0, sticky=W)
    sendChatButton.grid(row=0, column=1, padx=5)
    TerminateChatButton.grid(row=0, column=2, padx=5)

    self.statusLabel = Label(parentFrame)

    bottomLabel = Label(parentFrame, text="Created by Siddhartha under Prof. A. Prakash [Computer Networks, Dept. of CSE, BIT Mesra]")
    
    ipGroup.grid(row=0, column=0)
    readChatGroup.grid(row=1, column=0)
    writeChatGroup.grid(row=2, column=0, pady=10)
    self.statusLabel.grid(row=3, column=0)
    bottomLabel.grid(row=4, column=0, pady=10)

  #This function handle will Server initialization. it will open the listening socket and set serverStatus to 1 when Server is up. it is called when Server set button is pressed.
  def handleSetServer(self):
    if self.serverSoc != None:
        self.serverSoc.close()
        self.serverSoc = None
        self.serverStatus = 0
    serveraddr = (self.serverIPVar.get().replace(' ',''), int(self.serverPortVar.get().replace(' ','')))
    try:
        self.serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSoc.bind(serveraddr)
        self.serverSoc.listen(5)
        self.setStatus("Server listening on %s:%s" % serveraddr)
        #Print the key.
        ####################################################
        ####################################################
        print "\nold Bob hashed key (Hash of Securely Random)"
        print binascii.hexlify(bytearray(self.hashed_key)) 
        print "\n"
        ####################################################
        ####################################################
        thread.start_new_thread(self.listenClients,())
        self.serverStatus = 1
        self.name = self.nameVar.get().replace(' ','')
        if self.name == '':
            self.name = "%s:%s" % serveraddr
    except:
        self.setStatus("Error setting up server")
  
  #This function is part of Server components, where it will keep listening for any peer trying to connect after Server ip and port are set.
  def listenClients(self):
    while 1:
      clientsoc, clientaddr = self.serverSoc.accept()
      self.setStatus("Client connected from %s:%s" % clientaddr)
      self.addClient(clientsoc, clientaddr)
      thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
    self.serverSoc.close()
  
  #This function is part of Server components, where it will try to add the peers to the chat when "Add" as a friend is pressed.
  def handleAddClient(self):
    if self.serverStatus == 0:
      self.setStatus("Set server address first")
      return
    clientaddr = (self.clientIPVar.get().replace(' ',''), int(self.clientPortVar.get().replace(' ','')))
    try:
        clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsoc.connect(clientaddr)
        self.setStatus("Trying to connect to client on %s:%s" % clientaddr)
        self.addClient(clientsoc, clientaddr)
        thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
    except:
        self.setStatus("Error connecting to client")

  #This function is part of P2P components, where it handle the sent message by other peers.
  def handleClientMessages(self, clientsoc, clientaddr):
    global message1_rec, message3_rec
    while 1:
      try:
          #Handling Alice's message
          ####################################################
          if(not message1_rec):
            data = clientsoc.recv(2048)
            send_me = self.Bob_Step_2(Alice_IP=clientaddr[0], Bob_IP=self.serverIPVar.get().replace(' ',''), Alice_message=data)
            for client in self.allClients.keys():
              client.send(send_me)
            message1_rec = True
          elif(not message3_rec):
            data = clientsoc.recv(2048)
            check = self.Bob_Step_4(Alice_IP=clientaddr[0], Alice_message=data)
            if(check==False):
              print "Alice is not Authenticated! terminate! \n"
              msg = "Alice is not Authenticated!"
              del self.hashed_key
              for client in self.allClients.keys():
                client.send(msg)
              self.root.destroy()
            else:
              print "Alice has been authenticated! \n"
            message3_rec = True
          else:
            data = clientsoc.recv(self.buffsize)
            if not data:
                break
            #####################
            #####################
            #Decrypt the encrypted message
            data = self.Decryption(data, self.hashed_key)
            #####################
            #####################
            self.addChat("%s:%s" % clientaddr, data)
      except:
          break
    self.removeClient(clientsoc, clientaddr)
    clientsoc.close()
    self.setStatus("Client disconnected from %s:%s" % clientaddr)
  
  #This function is part of P2P components, where it will send "chat box text" to all peers when "send" is pressed.
  def handleSendChat(self):
    if self.serverStatus == 0:
      self.setStatus("Set server address first")
      return
    msg = self.chatVar.get()
    if msg == '':
        return
    self.addChat("me", msg)
    #####################
    #Encrypted Message to be sent
    msg = self.Encryption(msg, self.hashed_key, self.iv)
    #####################
    for client in self.allClients.keys():
      client.send(msg)
  
  #This function is part of Client components, where it will terminate the chat when "terminate" is pressed.
  def handleTerminateChat(self):
    if self.serverStatus == 0:
      self.setStatus("You are not connected to a chat")
      return
    serveraddr = (self.serverIPVar.get().replace(' ',''), int(self.serverPortVar.get().replace(' ','')))
    msg = "Client %s:%s has terminated the chat" % serveraddr
    self.addChat("me", msg)
    #####################
    #####################
    #Encrypted Message to be sent
    msg = self.Encryption(msg, self.hashed_key, self.iv)
    #####################
    #####################
    del self.hashed_key
    for client in self.allClients.keys():
      client.send(msg)
    self.root.destroy()
  
  #This function is part of Client components, where it will only add peer name and the message to the chat box.
  def addChat(self, client, msg):
    self.receivedChats.config(state=NORMAL)
    self.receivedChats.insert("end",client+": "+msg+"\n")
    self.receivedChats.config(state=DISABLED)
  
  #This function is part of P2P components, where add the connected peer as a fiend to the list.
  def addClient(self, clientsoc, clientaddr):
    self.allClients[clientsoc]=self.counter
    self.counter += 1
    self.friends.insert(self.counter,"%s:%s" % clientaddr)
  
  #This function is part of Client components, where it will remove the disconnected peer from friend list.
  def removeClient(self, clientsoc, clientaddr):
      print self.allClients
      self.friends.delete(self.allClients[clientsoc])
      del self.allClients[clientsoc]
      del self.hashed_key
      print self.allClients
  
  #This function is part of UI components, where it will change the bottom text of program status.
  def setStatus(self, msg):
    self.statusLabel.config(text=msg)
    print msg

#This is the main function that will intiliaze the UI and run the program.
def main():  
  root = Tk()
  app = ChatClient(root)
  root.mainloop()  

#Running the program over the network.
if __name__ == '__main__':
  main()  