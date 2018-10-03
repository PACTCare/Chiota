namespace Chiota.Messenger.Usecase
{
  using System;
  using System.Collections.Generic;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Extensions;
  using Chiota.Messenger.Service;

  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

  public abstract class AbstractChatInteractor<TIn, T> : IUsecaseInteractor<TIn, T>
    where T : BaseResponse
  {
    protected AbstractChatInteractor(IMessenger messenger, IEncryption encryption)
    {
      this.Messenger = messenger;
      this.Encryption = encryption;
    }

    private IEncryption Encryption { get; }

    private IMessenger Messenger { get; }

    /// <inheritdoc />
    public abstract Task<T> ExecuteAsync(TIn request);

    protected async Task<string> GetChatPasswordSalt(Address chatKeyAddress, IAsymmetricKeyPair userKeyPair)
    {
      var messages = await this.Messenger.GetMessagesByAddressAsync(chatKeyAddress);
      var chatPasSalt = new List<string>();
      foreach (var message in messages)
      {
        try
        {
          var pasSalt = Encoding.UTF8.GetString(
            NtruEncryption.Key.Decrypt(userKeyPair, StripPayload(message.Payload).DecodeBytesFromTryteString()));
          if (pasSalt != string.Empty)
          {
            chatPasSalt.Add(pasSalt);
          }
        }
        catch
        {
          // ignored
        }
      }

      if (chatPasSalt.Count > 0)
      {
        return chatPasSalt[0];
      }

      throw new MessengerException(ResponseCode.ChatPasswordAndSaltCannotBeGenerated);
    }

    private static TryteString StripPayload(TryteString payload)
    {
      return payload.GetChunk(0, payload.Value.IndexOf(Constants.End.Value, StringComparison.Ordinal));
    }
  }
}