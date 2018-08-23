namespace Chiota.Messenger.Service
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  /// <summary>
  /// The Messenger interface.
  /// </summary>
  public interface IMessenger
  {
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