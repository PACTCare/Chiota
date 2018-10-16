## Accept Contact

After a user was sent a contact request, he can accept it. The parameters needed for that are described below. 

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