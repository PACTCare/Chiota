namespace Chiota.Messenger.Service.Parser
{
  using System;
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public class RequestContactBundleParser : IBundleParser
  {
    /// <inheritdoc />
    public List<Message> ParseBundle(Bundle bundle)
    {
      var messageTrytes = string.Empty;

      // multiple message per bundle?
      foreach (var transaction in bundle.Transactions)
      {
        if (transaction.Value < 0)
        {
          continue;
        }

        if (!transaction.Fragment.IsEmpty)
        {
          messageTrytes += transaction.Fragment.Value;
        }
      }

      if (!messageTrytes.Contains(Constants.End.Value))
      {
        return null;
      }

      var index = messageTrytes.IndexOf(Constants.End.Value, StringComparison.Ordinal);

      return new List<Message> { new Message(new TryteString(messageTrytes.Substring(0, index))) };
    }
  }
}