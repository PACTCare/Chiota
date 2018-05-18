namespace Chiota.Services
{
  using System;
  using System.Collections.Generic;

  using Tangle.Net.Entity;

  using Xamarin.Forms.Internals;

  public static class Converter
  {
    public static string EncodeBytesAsString(this byte[] byteArray)
    {
      string[] trytesArray = { "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" };

      var trytes = string.Empty;

      for (var i = 0; i < byteArray.Length; i++)
      {
        var value = byteArray[i];

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

    public static byte[] DecodeBytesFromTryteString(this TryteString tryteString)
    {
      string[] trytesArray = { "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" };

      var trytesAsString = tryteString.ToString();

      // If input length is odd, return null
      if (trytesAsString.Length % 2 != 0)
      {
        return null;
      }

      var byteList = new List<byte>();

      for (var i = 0; i < trytesAsString.Length; i += 2)
      {
        var firstValue = trytesArray.IndexOf(trytesAsString.Substring(i, 1));
        var secondValue = trytesArray.IndexOf(trytesAsString.Substring(i + 1, 1));

        var value = firstValue + (secondValue * 27);
        byteList.Add(Convert.ToByte(value));
      }

      return byteList.ToArray();
    }
  }
}
