namespace Chiota.Messenger.Service
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

  using Constants = Chiota.Messenger.Constants;

  /// <inheritdoc />
  /// <summary>
  /// The tangle messenger.
  /// </summary>
  public class TangleMessenger : IMessenger
  {
    public TangleMessenger(IIotaRepository repository)
    {
      this.Repository = repository;
    }

    private IIotaRepository Repository { get; }

    /// <inheritdoc />
    public async Task SendMessageAsync(Message message)
    {
      if (!message.HasKnownType)
      {
        throw new MessengerException(ResponseCode.MessengerException, new UnknownMessageException(message.Type));
      }

      try
      {
        var bundle = new Bundle();
        bundle.AddTransfer(
          new Transfer
            {
              Address = message.Receiver,
              Message = message.Payload,
              Tag = Constants.Tag,
              Timestamp = Timestamp.UnixSecondsTimestamp
            });

        bundle.Finalize();
        bundle.Sign();

        await this.Repository.SendTrytesAsync(bundle.Transactions);
      }
      catch (Exception exception)
      {
        throw new MessengerException(ResponseCode.MessengerException, exception);
      }
    }
  }
}