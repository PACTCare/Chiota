## Send Message

As chat address you should always input the current chat address, which can be obtained by calling the GetMessages usecase.

### Request
```csharp
public class SendMessageRequest
{
    /// <summary>
    /// Current address of the chat (obtained from GetMessagesResponse)
    /// </summary>
    public Address ChatAddress { get; set; }

    /// <summary>
    /// Optional. Will be generated at runtime, if necessary. ChatKeyAddress and UserKeyPair must be set, if ChatKeyPair is null
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }

    /// <summary>
    /// Must be set if ChatKeyPair is null
    /// </summary>
    public Address ChatKeyAddress { get; set; }

    /// <summary>
    /// Must be set if ChatKeyPair is null
    /// </summary>
    public IAsymmetricKeyPair UserKeyPair { get; set; }

    /// <summary>
    /// The message to send
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// Public key address of the current user
    /// </summary>
    public Address UserPublicKeyAddress { get; set; }
}
```

### Response
```csharp
  public class SendMessageResponse : BaseResponse
  {
    /// <summary>
    /// ChatKeyPair from the request or the generated one, if the request pair was not set
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }
  }
```

### Usage
```csharp
var response = await this.SendMessageInteractor.ExecuteAsync(
        new SendMessageRequest
        {
            ChatAddress = this.currentChatAddress,
            ChatKeyPair = this.ntruChatKeyPair,
            Message = this.OutGoingText,
            UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
            ChatKeyAddress = new Address(this.contact.ChatKeyAddress),
            UserKeyPair = UserService.CurrentUser.NtruKeyPair
        });

this.ntruChatKeyPair = response.ChatKeyPair;
```