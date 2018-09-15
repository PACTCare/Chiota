namespace Chiota.Services
{
  using System;
  using System.Text;

  public static class Helper
  {
    public static string TryteStringIncrement(string tryteString)
    {
      // e.g. for "AAAAA" 10.596.375 possibilities
      var counter = 0;
      foreach (var character in tryteString)
      {
        if (character == '9' || character == 'Z')
        {
          counter++;
        }
        else
        {
          // increments one letter
          // ZAC - ZBC
          var strBuilder = new StringBuilder(tryteString) { [counter] = (char)(Convert.ToUInt16(character) + 1) };
          if (counter != 0)
          {
            // ABC
            strBuilder[counter - 1] = 'A';
          }

          tryteString = strBuilder.ToString();
          break;
        }
      }

      return tryteString;
    }
  }
}
