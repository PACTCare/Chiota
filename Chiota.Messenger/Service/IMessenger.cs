namespace Chiota.Messenger.Service
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service.Parser;

  using Tangle.Net.Entity;

  public interface IMessenger
  {
    Task<List<Message>> GetMessagesByAddressAsync(Address address, IBundleParser bundleParser);

    Task SendMessageAsync(Message message);
  }
}