## About

The Chiota Messenger represents the core component of Chiota. This document has the objective to give you an overview of how to use the Messenger in your applications.

## Flow

Assume you have two users, "Chantal" and "Kevin" that want to communicate through a secured channel. To set up their channel the following has to be done:

1) Create User "Kevin" and "Chantal"
2) One user has to send a contact request to the other
3) The contact request has to be accepted
4) They can now chat within their own secure channel

You can have a look at the [cucumber](https://github.com/Noc2/Chiota/tree/master/Chiota.Messenger.Cucumber/Features) tests to see how things are set up codewise or read the usecase descriptions below.

## Usecases

The Messenger follows a usecase orientated approach. The code snippets for every usecase reflect how it is used in Chiota.

![cleanarch](http://i.imgur.com/WkBAATy.png)

More information:
http://blog.8thlight.com/uncle-bob/2012/08/13/the-clean-architecture.html

### Create User

Usecase to initially create a user. Simply input the users seed. All necessary user information will be uploaded to the tangle and returned in the response.

```
var request = new CreateUserRequest { Seed = seed };
var response = await this.CreateUserInteractor.ExecuteAsync(request);

return new User
    {
        ...
        PublicKeyAddress = response.PublicKeyAddress.Value, 
        RequestAddress = response.RequestAddress.Value,
        NtruKeyPair = response.NtruKeyPair
        ...
    };
```

### Check User

To handle user information erased during a snapshot you can use the CheckUserInteractor. Chiota calls it on login. The interactor itself checks whether the required user information exists on the tangle and reuploads it if necessary.

```
var response = await this.CheckUserInteractor.ExecuteAsync(
        new CheckUserRequest
          {
            PublicKey = user.NtruKeyPair.PublicKey,
            PublicKeyAddress = new Address(user.PublicKeyAddress),
            RequestAddress = new Address(user.RequestAddress),
            Seed = new Seed(user.Seed)
          });
```

### Add Contact

Assuming a user (Sender) wants to interact with another (Receiver), he/she may want to send a contact request. Simply input the senders information along with the receivers request address (as contact address).

```
var response = await this.AddContactInteractor.ExecuteAsync(
        new AddContactRequest
        {
            Name = UserService.CurrentUser.Name,
            ImagePath = UserService.CurrentUser.ImageHash,
            RequestAddress = new Address(UserService.CurrentUser.RequestAddress),
            PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
            ContactAddress = new Address(this.RequestAddress)
        });
```

### Accept Contact

To accept a contact request just invoke the accept contact interactor. (If the code below is not explanation enough, please let me know how it can be improved)

```
var response = await this.AcceptContactInteractor.ExecuteAsync(
        new AcceptContactRequest
            {
            UserName = UserService.CurrentUser.Name,
            UserImagePath = UserService.CurrentUser.ImageHash,
            ChatAddress = new Address(this.Contact.ChatAddress),
            ChatKeyAddress = new Address(this.Contact.ChatKeyAddress),
            ContactAddress = new Address(this.Contact.ContactAddress),
            ContactPublicKeyAddress = new Address(this.Contact.PublicKeyAddress),
            UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
            UserKeyPair = UserService.CurrentUser.NtruKeyPair,
            UserContactAddress = new Address(UserService.CurrentUser.RequestAddress)
            });
```

### Decline Contact

Similar to accept contact, a user might want to decline a contact request. Please note, that on a different device, the contact request will (currently) be shown as pending again.

```
await this.DeclineContactInteractor.ExecuteAsync(
        new DeclineContactRequest
          {
            ContactChatAddress = new Address(this.Contact.ChatAddress),
            UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
          });
```

### Get Contacts

```
var response = await interactor.ExecuteAsync(
        new GetContactsRequest
            {
            ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
            PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

```
```
public class GetContactsResponse : BaseResponse
{
    public List<Contact> ApprovedContacts { get; set; }

    public List<Contact> PendingContactRequests { get; set; }
}
```

### Send Message

### Get Messages

## Entities