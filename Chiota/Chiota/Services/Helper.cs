namespace Chiota.Services
{
  using System;
  using System.Net;
  using System.Text;
  using System.Threading.Tasks;

  using Chiota.Models;
  using Chiota.Services.AvatarStorage;
  using Chiota.Services.DependencyInjection;

  using Tangle.Net.Entity;

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

    public static Address GenerateAddress(Address baseAddress)
    {
      var addressString = baseAddress.ToString();
      var length = addressString.Length;
      addressString = addressString.Substring(0, length - 12) + TryteStringIncrement(addressString.Substring(length - 12, 12));
      return new Address(addressString);
    }

    public static string ImageNameGenerator(string name, string publicKeyAddress)
    {
      return publicKeyAddress.Substring(0, 10) + name;
    }

    public static async Task UploadImageForNewUser(string contactAddress, User user)
    {
      var ntru = new NtruKex();
      var decrypt = ntru.Decrypt(user.NtruKeyPair, DownloadByteArray(user.ImageUrl));

      // encrypt for new user with public pair, slower
      var enryptedImage = ntru.Encrypt(user.NtruKeyPair.PublicKey, decrypt);
      user.ImageUrl = await DependencyResolver.Resolve<IAvatarStorage>().UploadEncryptedAsync(ImageNameGenerator(user.Name, user.PublicKeyAddress) + contactAddress.Substring(0, 5), enryptedImage);
    }

    public static byte[] DownloadByteArray(string imageUrl)
    {
      using (var wc = new WebClient())
      {
        return wc.DownloadData(imageUrl);
      }
    }
  }
}
