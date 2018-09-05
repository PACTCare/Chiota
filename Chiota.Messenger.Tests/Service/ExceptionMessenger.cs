namespace Chiota.Messenger.Tests.Service
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Entity;

  /// <summary>
  /// The exception messenger.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class ExceptionMessenger : IMessenger
  {
    public ExceptionMessenger(Exception exception = null)
    {
      this.Exception = exception;
    }

    private Exception Exception { get; }

    /// <inheritdoc />
    public Task<List<Message>> GetMessagesByAddressAsync(Address address)
    {
      return null;
    }

    /// <inheritdoc />
    public Task SendMessageAsync(Message message)
    {
      if (this.Exception != null)
      {
        throw this.Exception;
      }

      throw new MessengerException(ResponseCode.MessengerException, null);
    }
  }
}