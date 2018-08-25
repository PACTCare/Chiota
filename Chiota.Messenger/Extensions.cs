namespace Chiota.Messenger
{
  /// <summary>
  /// The extensions.
  /// </summary>
  internal static class Extensions
  {
    /// <summary>
    /// The encode bytes as string.
    /// </summary>
    /// <param name="byteArray">
    /// The byte array.
    /// </param>
    /// <returns>
    /// The <see cref="string"/>.
    /// </returns>
    public static string EncodeBytesAsString(this byte[] byteArray)
    {
      string[] trytesArray =
        {
          "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
        };

      var trytes = string.Empty;

      foreach (var value in byteArray)
      {
        // If outside bounderies of a byte, return null
        if (value > 255)
        {
          return null;
        }

        var firstValue = value % 27;
        var secondValue = (value - firstValue) / 27;

        var trytesValue = trytesArray[firstValue] + trytesArray[secondValue];

        trytes += trytesValue;
      }

      return trytes;
    }
  }
}