namespace Chiota.Models
{
  using System.Collections.Generic;

  using Chiota.IOTAServices;

  using Tangle.Net.Entity;

  public class UserFactory : IUserFactory
  {
    public User Create(Seed storeSeed, List<Address> addresses)
    {
      return new User()
      {
        Name = null,
        Seed = storeSeed,
        ImageUrl = null,
        StoreSeed = false,
        OwnDataAdress = addresses[0].Value,
        PublicKeyAddress = addresses[1].Value, // + addresses[1].WithChecksum().Checksum.Value,
        RequestAddress = addresses[2].Value,
        ApprovedAddress = addresses[3].Value,
        TangleMessenger = new TangleMessenger(storeSeed)
    };
    }

    public OwnDataUser CreateUploadUser(User user)
    {
      return new OwnDataUser()
      {
        Name = user.Name,

        // store only filename plus type on tangle
        ImageUrl = user.ImageUrl.Replace(ChiotaConstants.ImagePath, string.Empty)
      };
    }
  }
}
