namespace Chiota.Messenger.Usecase.AcceptContact
{
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  /// <summary>
  /// The accept contact request.
  /// </summary>
  public class AcceptContactRequest
  {
    public Address ChatAddress { get; set; }

    public Address ChatKeyAddress { get; set; }

    public Address ContactAddress { get; set; }

    public Address ContactPublicKeyAddress { get; set; }

    public Address UserContactAddress { get; set; }

    public string UserImageHash { get; set; }

    public IAsymmetricKeyPair UserKeyPair { get; set; }

    public string UserName { get; set; }

    public Address UserPublicKeyAddress { get; set; }
  }
}