namespace Chiota.Messenger.Tests.Service
{
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Linq;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;

  using Tangle.Net.Entity;

  /// <summary>
  /// The in memory messenger.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class InMemoryMessenger : IMessenger
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryMessenger"/> class.
    /// </summary>
    public InMemoryMessenger()
    {
      this.SentMessages = new List<Message>();
    }

    /// <summary>
    /// Gets or sets the sent messages.
    /// </summary>
    public List<Message> SentMessages { get; set; }

    /// <inheritdoc />
    public async Task<List<Message>> GetMessagesByAddressAsync(Address address, IBundleParser bundleParser)
    {
      return this.SentMessages.Where(m => m.Receiver.Value == address.Value).ToList();
    }

    /// <inheritdoc />
    public async Task SendMessageAsync(Message message)
    {
      this.SentMessages.Add(message);
    }
  }
}