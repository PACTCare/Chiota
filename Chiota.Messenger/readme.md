# About

The Chiota Messenger represents the core component of Chiota. This document has the objective to give you an overview of how to use the Messenger in your applications.

# Flow

Assume you have two users, "Chantal" and "Kevin", who want to communicate through a secured channel. To set up their channel the following has to be done:

1) Create User "Kevin" and "Chantal"
2) One user has to send a contact request to the other
3) The contact request has to be accepted
4) They can now chat within their own secure channel

You can have a look at the [cucumber](https://github.com/Noc2/Chiota/tree/master/Chiota.Messenger.Cucumber/Features) tests to see how things are set up codewise or read the usecase descriptions below.

# Usecases

The Messenger follows a usecase orientated approach. The code snippets for every usecase reflect how it is used in Chiota.

![cleanarch](http://i.imgur.com/WkBAATy.png)

More information:
http://blog.8thlight.com/uncle-bob/2012/08/13/the-clean-architecture.html

## Create User

Usecase to initially create a user. Simply input the users seed. All necessary user information will be uploaded to the tangle and returned in the response.

### Request
```csharp
public class CreateUserRequest
{
    /// <summary>
    /// The seed associated with the user. User data will be derived from the seed.
    /// </summary>
    public Seed Seed { get; set; }
}
```
### Response
```csharp
public class CreateUserResponse : BaseResponse
{
    /// <summary>
    /// Address where the users' public key is stored
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// Other users can add the user by using this address
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// Key pair generated from seed, used for encryption
    /// </summary>
    public IAsymmetricKeyPair NtruKeyPair { get; set; }
}
```

### Usage
```csharp
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

## Check User

To handle user information erased during a snapshot you can use the CheckUserInteractor. Chiota calls it on login. The interactor itself checks whether the required user information exists on the tangle and reuploads it if necessary.

### Request
```csharp
public class CheckUserRequest
{
    /// <summary>
    /// Public key of the user to check (See CreateUserResponse)
    /// </summary>
    public IAsymmetricKey PublicKey { get; set; }

    /// <summary>
    /// Public Key address of the user (See CreateUserResponse)
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// (Contact) request address of the user (See CreateUserResponse)
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// Seed associated with the user
    /// </summary>
    public Seed Seed { get; set; }
}
```

### Usage
```csharp
var response = await this.CheckUserInteractor.ExecuteAsync(
        new CheckUserRequest
          {
            PublicKey = user.NtruKeyPair.PublicKey,
            PublicKeyAddress = new Address(user.PublicKeyAddress),
            RequestAddress = new Address(user.RequestAddress),
            Seed = new Seed(user.Seed)
          });
```

## Add Contact

Assuming a user (Sender) wants to interact with another (Receiver), he/she may want to send a contact request. Simply input the senders information along with the receivers request address (as contact address).

### Request
```csharp
public class AddContactRequest
{
    /// <summary>
    /// Request address of the contact that should be added
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// Optional: Image that will be shown to the added contact within the contact request
    /// </summary>
    public string ImagePath { get; set; }

    /// <summary>
    /// Current user name. Will be shown to the contact within the contact request
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// Request address of the current user
    /// </summary>
    public Address RequestAddress { get; set; }
}
```

### Usage
```csharp
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

## Get Contacts

### Request
```csharp
public class GetContactsRequest
{
    /// <summary>
    /// The current user request address (See CreateUserResponse)
    /// </summary>
    public Address RequestAddress { get; set; }

    /// <summary>
    /// The current user public key address (See CreateUserResponse)
    /// </summary>
    public Address PublicKeyAddress { get; set; }

    /// <summary>
    /// If set to true, checks all pending contacts to determine whether they are accepted or not.
    /// Normally not needed since the information is stored in the IContactRepository (locally).
    /// Useful to import a existing seed into a new device
    /// </summary>
    public bool DoCrossCheck { get; set; }
}
```

### Response
```csharp
public class GetContactsResponse : BaseResponse
{
    /// <summary>
    /// All contacts that have been accepted. See Entities for more information about the Contact class
    /// </summary>
    public List<Contact> ApprovedContacts { get; set; }

    /// <summary>
    /// All contacts that have a open request. See Entities for more information about the Contact class
    /// </summary>
    public List<Contact> PendingContactRequests { get; set; }
}
```

### Usage
```csharp
var response = await interactor.ExecuteAsync(
        new GetContactsRequest
            {
            ContactRequestAddress = new Address(UserService.CurrentUser.RequestAddress),
            PublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
            });

```

## Accept Contact

To accept a contact request just invoke the accept contact interactor. 

### Request
```csharp
public class AcceptContactRequest
{
    /// <summary>
    /// The chat address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ChatAddress { get; set; }

    /// <summary>
    /// The chat key address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ChatKeyAddress { get; set; }

    /// <summary>
    /// The contact address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ContactAddress { get; set; }

    /// <summary>
    /// The contact public key address that was passed along with the request. (See Contact from GetContactsUsecase)
    /// </summary>
    public Address ContactPublicKeyAddress { get; set; }

    /// <summary>
    /// The contact address of the current user. 
    /// </summary>
    public Address UserContactAddress { get; set; }

    /// <summary>
    /// Image path of the users avatar or similar
    /// </summary>
    public string UserImagePath { get; set; }

    /// <summary>
    /// The key pair of the current user. Used for chat encryption
    /// </summary>
    public IAsymmetricKeyPair UserKeyPair { get; set; }

    /// <summary>
    /// Current user name
    /// </summary>
    public string UserName { get; set; }

    /// <summary>
    /// The users public key address
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
}
```

### Usage
```csharp
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

## Decline Contact

Similar to accept contact, a user might want to decline a contact request. Please note, that on a different device, the contact request will (currently) be shown as pending again.

### Request
```csharp
public class DeclineContactRequest
{
    /// <summary>
    /// Chat address included in the contacts request
    /// </summary>
    public Address ContactChatAddress { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
}
```

### Usage
```csharp
await this.DeclineContactInteractor.ExecuteAsync(
        new DeclineContactRequest
          {
            ContactChatAddress = new Address(this.Contact.ChatAddress),
            UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress)
          });
```

## Send Message

## Get Messages

# Entities