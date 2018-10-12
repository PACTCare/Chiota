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