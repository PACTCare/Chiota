namespace Chiota.Messenger.Extensions
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;

  using Tangle.Net.Entity;

  public static class TryteStringExtensions
  {
    public static TryteString Increment(this TryteString tryteString)
    {
      // e.g. for "AAAAA" 10.596.375 possibilities
      var counter = 0;
      foreach (var character in tryteString.Value)
      {
        if (character == '9' || character == 'Z')
        {
          counter++;
        }
        else
        {
          // increments one letter
          // ZAC - ZBC
          var strBuilder = new StringBuilder(tryteString.Value) { [counter] = (char)(Convert.ToUInt16(character) + 1) };
          if (counter != 0)
          {
            // ABC
            strBuilder[counter - 1] = 'A';
          }

          return new TryteString(strBuilder.ToString());
        }
      }

      return tryteString;
    }

    public static Address DeriveRequestAddress(this Address baseAddress)
    {
      var trytes = baseAddress.GetChunk(0, Address.Length - 12).Concat(baseAddress.GetChunk(Address.Length - 12, 12).Increment());
      return new Address(trytes.Value);
    }
  }
}