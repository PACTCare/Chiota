# Chiota
Chiota is an [IOTA](http://iota.org/) [Xamarin](https://www.xamarin.com/) Chat App based on [Felandils C# .NET Port of the IOTA lib](https://github.com/Felandil/tangle-.net), who also helped with this app, [Steppenwolfe65 CEX-NET](https://github.com/Steppenwolfe65/CEX-NET) and [jamesmontemagnos MonkeyChat](https://github.com/jamesmontemagno/app-monkeychat).  

The goal is to create a quantum secure chat app, in which you are the owner of your own data and nobody else! 

Impressions of the current state:

<img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180406-180427.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180402-123945.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180406-180148.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180402-124908.jpg" width="200">

# How Chiota works?
See the [GitHub Wiki](https://github.com/Noc2/Chiota/wiki) for more detailed information about the different modules of Chiota. 

Chiota doesn’t use the MAM Layer for sending secure messages. Instead, it uses the NTRU Encryption (see [NTRU Key Exchange for IOTA](https://github.com/Noc2/Chiota/wiki/NTRU-Key-Exchange-for-IOTA) for more details). 
There are several reasons for that:
-	NTRU or some other form of key exchange is needed for the MAM-Layer anyway
-	For the MAM Layer, you have a lot of different transactions and currently, the proof-of-work takes really long, so the goal is to reduce the number of necessary transactions
-	You need to store the state of the MAM Layer (root hash, channel keys, etc.). If you want to store these things quantum secure on the tangle it results in more messages and therefore additional PoW

The disadvantage of the current system:
-	You are limited to 105 characters per transaction because the NTRU encryption needs more space 
-	Advances in cryptanalysis may at some point break NTRU

# Motivation
During the process of creating the health care chatbot Florence, we found out that we can't use the technology to its full potential due to various problems with the current state of the healthcare system. **You as a patient should be in control of your healthcare data and a chatbot should support the private, secure and continuous communication between you and your healthcare provider network.** However, with the current technology that isn't possible. That is why we started the project **“Untangle Care”**, you can find out more about it on the [official IOTA ecosystem page](https://ecosystem.iota.org/projects/untangle-care). 

# About us/me
My name is David Hawig and I am the developer of Florence.chat.  You can contact me on [linkedin](https://www.linkedin.com/in/david-hawig-206a44b1/) or via Mail (david.hawig[at]florence[dot]chat). 
My current Chiota contact address is OZQQEPQ9AH9QUX9BQAWOBCTZNAFIFYYWMZUDKFUKGQAIEFAXBZKWCMMOXFU9PDCAMAHDIUTCZPZK9RKPZ

We welcome any kind of help or contribution!

# To-do/Contribute
If you want to test this code, you have either to remove the blob storage (see [BlobStorage.cs](https://github.com/Noc2/Chiota/blob/master/Chiota/Chiota/Services/BlobStorage.cs#L15)) or replace it with your image storage. I currently store only links to images on the tangle. 

Currently, there are the following points on my to-do list:
- [x] Store contacts/profile on the tangle
- [x] Qr codes for address sharing
- [x] Performance improvements
- [x] Check for unique Address public key combination
- [x] Notifications
- [x] Change address after a certain number of messages 
- [x] Chatbot integration
- [x] Local SQLite Database for storage of encrypted messages (snapshot)
- [ ] Improve performance/Fix errors
- [ ] Android versions/iOS App
- [ ] Unit testing
- [ ] Code refactoring

# Donate
```
GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW9IYHJNNRX 
```
