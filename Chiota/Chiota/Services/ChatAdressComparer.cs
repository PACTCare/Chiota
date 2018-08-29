namespace Chiota.Services
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  public class ChatAdressComparer : IEqualityComparer<Contact>
  {
    public int GetHashCode(Contact co)
    {
      return co.ChatAddress.GetHashCode();
    }

    public bool Equals(Contact x1, Contact x2)
    {
      if (ReferenceEquals(x1, x2))
      {
        return true;
      }

      if (x1 is null || x2 is null)
      {
        return false;
      }

      return x1.ChatAddress == x2.ChatAddress;
    }
  }
}
