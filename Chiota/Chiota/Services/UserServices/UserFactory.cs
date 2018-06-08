namespace Chiota.Services.UserServices
{
  using System.Collections.Generic;

  using Chiota.IOTAServices;
  using Chiota.Models;

  using Tangle.Net.Entity;

  /// <inheritdoc />
  public class UserFactory : IUserFactory
  {
    /// <inheritdoc />
    public User Create(Seed seed, List<Address> addresses)
    {
      return new User
               {
                 Name = null,
                 Seed = seed,
                 ImageUrl = null,
                 StoreSeed = false,
                 OwnDataAdress = addresses[0].Value,
                 PublicKeyAddress = addresses[1].Value, // + addresses[1].WithChecksum().Checksum.Value,
                 RequestAddress = addresses[2].Value,
                 ApprovedAddress = addresses[3].Value,
                 TangleMessenger = new TangleMessenger(seed)
               };
    }
  }
}
