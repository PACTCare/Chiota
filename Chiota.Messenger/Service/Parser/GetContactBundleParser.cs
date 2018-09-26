namespace Chiota.Messenger.Service.Parser
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public class GetContactBundleParser : IBundleParser
  {
    /// <inheritdoc />
    public List<Message> ParseBundle(Bundle bundle)
    {
      var messages = new List<Message>();
      foreach (var contactMessage in bundle.GetMessages())
      {
        messages.Add(new Message(TryteString.FromUtf8String(contactMessage)));
      }

      return messages;
    }
  }
}