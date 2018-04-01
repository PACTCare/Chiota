namespace Chiota.IOTAServices
{
  using System.Collections.Generic;

  using Tangle.Net.Entity;

  public class HashesComparer : IEqualityComparer<Hash>
  {
    public bool Equals(Hash x, Hash y)
    {
      if (ReferenceEquals(x, y))
      {
        return true;
      }

      if (x is null || y is null)
      {
        return false;
      }

      return x.Value == y.Value;
    }

    public int GetHashCode(Hash obj)
    {
      return obj == null ? 0 : obj.GetHashCode();
    }
  }
}
