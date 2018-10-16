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