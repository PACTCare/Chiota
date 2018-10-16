## Get Messages

Loads all messages from the ChatAddress on. The behaviour is similar to MAM, where the chat address from GetContacts is the first one. For any six messages a new chat address is generated automatically and returned in the response.

Chiota just sets the current chat address to the one included in the response. 

That way only messages from that chat address on are fetched.

### Request
```csharp
public class GetMessagesRequest
{
    /// <summary>
    /// The current address of the chat 
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
}
```

### Response
```csharp
public class GetMessagesResponse : BaseResponse
{
    /// <summary>
    /// Current address of the conversation. Acts as a pointer. Input into request to start getting message from that point in conversation
    /// </summary>
    public Address CurrentChatAddress { get; set; }

    /// <summary>
    /// List of messages
    /// </summary>
    public List<ChatMessage> Messages { get; set; }

    /// <summary>
    /// ChatKeyPair from the request or the generated one, if the request pair was not set
    /// </summary>
    public IAsymmetricKeyPair ChatKeyPair { get; set; }
}
```

### Usage
```csharp
var response = await this.GetMessagesInteractor.ExecuteAsync(
                            new GetMessagesRequest
                            {
                                ChatAddress = this.currentChatAddress,
                                ChatKeyPair = this.ntruChatKeyPair,
                                ChatKeyAddress = new Address(this.contact.ChatKeyAddress),
                                UserKeyPair = UserService.CurrentUser.NtruKeyPair
                            });

this.currentChatAddress = response.CurrentChatAddress;
this.ntruChatKeyPair = response.ChatKeyPair;
```