namespace Chiota.Messenger.Service
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Models;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;
  using Tangle.Net.Repository;
  using Tangle.Net.Utils;

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
        throw new UnknownMessageException(message.Type);
      }

      var bundle = new Bundle();
      bundle.AddTransfer(
        new Transfer
          {
            Address = message.Receiver,
            Message = message.Payload,
            Tag = new Tag(ChiotaConstants.Tag),
            Timestamp = Timestamp.UnixSecondsTimestamp
          });

      bundle.Finalize();
      bundle.Sign();

      await this.Repository.SendTrytesAsync(bundle.Transactions);
    }
  }
}