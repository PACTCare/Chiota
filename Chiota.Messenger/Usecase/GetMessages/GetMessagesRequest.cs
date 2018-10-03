namespace Chiota.Messenger.Usecase.GetMessages
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public class GetMessagesRequest
  {
    public Address ChatAddress { get; set; }

    public IAsymmetricKeyPair ChatKeyPair { get; set; }
  }
}