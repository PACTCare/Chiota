namespace Chiota.Services
{
  using System.Collections.Generic;

  using Chiota.Models;

  public class ChatAdressComparer : IEqualityComparer<Contact>
  {
    public int GetHashCode(Contact co)
    {
      return co == null ? 0 : co.ChatAdress.GetHashCode();
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

      return x1.ChatAdress == x2.ChatAdress;
    }
  }
}
