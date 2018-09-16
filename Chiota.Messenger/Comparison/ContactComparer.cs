namespace Chiota.Messenger.Comparison
{
  using System.Collections.Generic;

  using Chiota.Messenger.Entity;

  /// <summary>
  /// The chat adress comparer.
  /// </summary>
  public class ContactComparer : IEqualityComparer<Contact>
  {
    /// <summary>
    /// The equals.
    /// </summary>
    /// <param name="x1">
    /// The x 1.
    /// </param>
    /// <param name="x2">
    /// The x 2.
    /// </param>
    /// <returns>
    /// The <see cref="bool"/>.
    /// </returns>
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

    /// <summary>
    /// The get hash code.
    /// </summary>
    /// <param name="co">
    /// The co.
    /// </param>
    /// <returns>
    /// The <see cref="int"/>.
    /// </returns>
    public int GetHashCode(Contact co)
    {
      return co.ChatAddress.GetHashCode();
    }
  }
}