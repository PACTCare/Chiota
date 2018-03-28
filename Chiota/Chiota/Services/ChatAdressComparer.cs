namespace Chiota.Services
{
  using System.Collections.Generic;

  using Chiota.Models;

  public class ChatAdressComparer : IEqualityComparer<SentDataWrapper<Contact>>
  {
    public int GetHashCode(SentDataWrapper<Contact> co)
    {
      return co == null ? 0 : co.Data.ContactAdress.GetHashCode();
    }

    public bool Equals(SentDataWrapper<Contact> x1, SentDataWrapper<Contact> x2)
    {
      if (ReferenceEquals(x1, x2))
      {
        return true;
      }

      if (x1 is null || x2 is null)
      {
        return false;
      }

      return x1.Data.ContactAdress == x2.Data.ContactAdress;
    }
  }
}
