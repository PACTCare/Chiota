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