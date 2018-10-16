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