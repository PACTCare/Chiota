namespace Chiota.Messenger.Usecase.GetMessages
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class GetMessagesRequest
  {
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
}