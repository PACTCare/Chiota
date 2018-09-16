namespace Chiota.Messenger.Service.Parser
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  using Tangle.Net.Entity;

  public interface IBundleParser
  {
    List<Message> ParseBundle(Bundle bundle);
  }
}