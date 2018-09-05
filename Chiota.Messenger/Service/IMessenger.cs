namespace Chiota.Messenger.Service
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  /// <summary>
  /// The Messenger interface.
  /// </summary>
  public interface IMessenger
  {
    /// <summary>
    /// The get messages by address async.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task<List<Message>> GetMessagesByAddressAsync(Address address);

    /// <summary>
    /// The send message async.
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    Task SendMessageAsync(Message message);
  }
}