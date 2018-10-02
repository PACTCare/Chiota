namespace Chiota.Messenger.Service.Parser
{
  using System.Collections.Generic;
  using System.Linq;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public class ChatMessageBundleParser : IBundleParser
  {
    /// <inheritdoc />
    public List<Message> ParseBundle(Bundle bundle)
    {
      var trytes = bundle.Transactions.Aggregate(new TryteString(), (current, tryteString) => current.Concat(tryteString.Fragment));
      return new List<Message> { new Message(trytes) };
    }
  }
}