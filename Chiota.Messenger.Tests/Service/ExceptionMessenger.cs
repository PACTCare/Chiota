namespace Chiota.Messenger.Tests.Service
{
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;

  /// <summary>
  /// The exception messenger.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class ExceptionMessenger : IMessenger
  {
    /// <inheritdoc />
    public Task SendMessageAsync(Message message)
    {
      throw new MessengerException(ResponseCode.MessengerException, null);
    }
  }
}