namespace Chiota.Messenger.Service
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public interface IMessenger
  {
    Task<List<Message>> GetMessagesByAddressAsync(Address address);

    Task SendMessageAsync(Message message);
  }
}