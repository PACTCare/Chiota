namespace Chiota.Models
{
  using System.Collections.Generic;

  using Chiota.IOTAServices;
  using Chiota.Services;

  using Tangle.Net.Entity;

  public class UserFactory
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
        PublicKeyAddress = addresses[1].Value,
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
        ImageUrl = user.ImageUrl,
      };
    }
  }
}
