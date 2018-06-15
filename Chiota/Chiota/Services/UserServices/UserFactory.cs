namespace Chiota.Services.UserServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.IOTAServices;
  using Chiota.Models;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  /// <inheritdoc />
  public class UserFactory : IUserFactory
  {
    /// <inheritdoc />
    public async Task<User> CreateAsync(Seed seed)
    {
      // 0. own user data address (encrypted, MAM or private key)
      // 1. public key address 
      // 2. request address
      // 3. approved address
      // addresses can be generated based on each other to make it faster
      var addresses = await Task.Run(() => new AddressGenerator().GetAddresses(seed, SecurityLevel.Medium, 0, 2));

      // var addresses = await this.GenerateAddressParallel(seed, 2);
      addresses.Add(Helper.GenerateAddress(addresses[0]));
      addresses.Add(Helper.GenerateAddress(addresses[1]));

      var user = new User
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

      var ntru = new NtruKex();
      user.NtruChatPair = ntru.CreateAsymmetricKeyPair(user.Seed.ToString().ToLower(), user.OwnDataAdress);
      user.NtruContactPair = ntru.CreateAsymmetricKeyPair(user.Seed.ToString().ToLower(), user.ApprovedAddress);

      return user;
    }
  }
}
