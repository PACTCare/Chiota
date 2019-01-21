# Chiota

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme) Chiota Android: [![Build status](https://florencechat.visualstudio.com/Chiota/_apis/build/status/Chiota%20Android)](https://florencechat.visualstudio.com/Chiota/_build/latest?definitionId=10) Messenger Package: [![Build status](https://florencechat.visualstudio.com/Chiota/_apis/build/status/Chiota%20Messenger%20Package)](https://florencechat.visualstudio.com/Chiota/_build/latest?definitionId=9)

> Your IOTA Chat App

Chiota is an [IOTA](http://iota.org/) [Xamarin](https://www.xamarin.com/) Chat App based on [Felandils C# .NET Port of the IOTA lib](https://github.com/Felandil/tangle-.net), [Steppenwolfe65 CEX-NET](https://github.com/Steppenwolfe65/CEX-NET) and [jamesmontemagnos MonkeyChat](https://github.com/jamesmontemagno/app-monkeychat).  

The goal is to create a quantum secure chat app, in which you are the owner of your own data and nobody else! 

Impressions of the current state:

<img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180406-180427.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180402-123945.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180406-180148.jpg" width="200"> <img src="https://chiota.blob.core.windows.net/screenshots/Screenshot_20180402-124908.jpg" width="200">

---

## Table of Contents

- [Background](#background)
  - [How Chiota works?](#how-chiota-works)
  - [Motivation](#motivation)
- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
  - [Donate](#donate)
  - [Code](#code)
- [License](#license)

## Background

### How Chiota works?
See the [GitHub Wiki](https://github.com/Noc2/Chiota/wiki) for more detailed information about the different modules of Chiota. 

Chiota doesn’t use the MAM Layer for sending secure messages. Instead, it uses the NTRU Encryption (see [NTRU Key Exchange for IOTA](https://github.com/Noc2/Chiota/wiki/NTRU-Key-Exchange-for-IOTA) for more details). 
There are several reasons for that:
-	NTRU or some other form of key exchange is needed for the MAM-Layer anyway
-	For the MAM Layer, you have a lot of different transactions and currently, the proof-of-work takes really long, so the goal is to reduce the number of necessary transactions
-	You need to store the state of the MAM Layer (root hash, channel keys, etc.). If you want to store these things quantum secure on the tangle it results in more messages and therefore additional PoW
- NTRU can be extremely fast, see [Speed records for NTRU](https://homes.esat.kuleuven.be/~fvercaut/papers/ntru_gpu.pdf) 

The disadvantage of the current system:
-	You are limited to less characters per transaction because the NTRU encryption needs more space 
-	Advances in cryptanalysis may at some point break NTRU

### Motivation
During the process of creating the health care chatbot Florence, we found out that we can't use the technology to its full potential due to various problems with the current state of the healthcare system. **You as a patient should be in control of your healthcare data and a chatbot should support the private, secure and continuous communication between you and your healthcare provider network.** However, with the current technology that isn't possible. That is why we started the project **“Untangle Care”**, you can find out more about it on the [official IOTA ecosystem page](https://ecosystem.iota.org/projects/untangle-care). 

## Install

## Usage

- Google Play beta test: https://play.google.com/apps/testing/chiotaapp.chiotaapp

## Maintainers

- [Simon Lang](https://github.com/ThunderSL)
- [Sebastian Fuhrhop](https://github.com/Felandil)

## Contributing
You can either support this project by [donating](#donate) or by contributing to the [code](#code). 

### Donate
IOTA Donation address
```
LRKZARMRXNBSUAOGYOMCRBAZAK9ZSVWTIXOVFTGTX9FRZVUNIM9NLBEZPPZIDD9MQHVCOFNELKGVCIYVWQGRWYZU9X 
```

### Code 
If you want to help either join our **[discord server](https://discord.gg/VMj7PFN)** or you can open issues for bugs you've found or features you think are missing. You can also submit pull requests to this repository.

If editing the README, please conform to the [standard-readme specification](https://github.com/RichardLitt/standard-readme).

## License
[MIT License](https://github.com/PACTCare/Chiota/blob/master/LICENSE) © PACT Care B.V.
