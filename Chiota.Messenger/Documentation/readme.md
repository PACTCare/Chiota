# About

The Chiota Messenger represents the core component of Chiota. This document has the objective to give you an overview of how to use the Messenger in your applications.

# Flow

Assume you have two users, "Chantal" and "Kevin", who want to communicate through a secured channel. To set up their channel the following has to be done:

1) Create User "Kevin" and "Chantal"
2) One user has to send a contact request to the other
3) The contact request has to be accepted
4) They can now chat within their own secure channel

You can have a look at the [cucumber](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger.Cucumber/Features) tests to see how things are set up codewise or read the usecase descriptions below.

# Usecases

The Messenger follows a usecase orientated approach. The code snippets for every usecase reflect how it is used in Chiota.

![cleanarch](http://i.imgur.com/WkBAATy.png)

More information:
http://blog.8thlight.com/uncle-bob/2012/08/13/the-clean-architecture.html

- [Create User](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/createuser.md)
- [Check User](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/checkuser.md)
- [Add Contact](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/addcontact.md)
- [Get Contacts](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/getcontacts.md)
- [Accept Contact](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/acceptcontact.md)
- [Decline Contact](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation//Usecasesdeclinecontact.md)
- [Send Message](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/sendmessage.md)
- [Get Messages](https://github.com/PACTCare/Chiota/tree/master/Chiota.Messenger/Documentation/Usecases/getmessages.md)

# Entities

While interactors are in place to orchestrate behaviour, entities are supposed to hold it. For details, just take a look at the Entity folder. 

You may notice that there currently is not so much business logic in them. That is a thing that will be addressed iteratively, while refactoring the interactors to be pure orchestrators.

# Repositories | Cache

For most modern applications it is not possible to be completely clean of outer dependencies. To handle those, repositories have been put in place, to inverse those dependencies.

The messenger module defines two repositories you have to implement yourself (You could start off with the in memory implementations for testing, but they will not get you far)

1) IContactRepository
    
    There are two options to implement this interface:<br>
    a) Implement the complete interface to use your own logic<br>
    b) Extend the AbstractTangleContactRepository, that already contains basic logic to load contacts from the tangle

2) ITransactionCache

    This repository caches all transactions received by the messenger. You should implement it in order to significantly speed up your application. In addition cached transactions can not be wiped in a snapshot, which can be useful