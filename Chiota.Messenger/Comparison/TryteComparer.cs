namespace Chiota.Messenger.Comparison
{
  using System.Collections.Generic;

  using Tangle.Net.Entity;

  /// <inheritdoc />
  /// <summary>
  /// The tryte comparer.
  /// </summary>
  public class TryteComparer<T> : IEqualityComparer<T> where T : TryteString
  {
    /// <inheritdoc />
    public bool Equals(T x, T y)
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

    /// <inheritdoc />
    public int GetHashCode(T trytes)
    {
      return 0;
    }
  }
}