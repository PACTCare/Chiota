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
    public async Task<User> Create(string seedInput, bool storeSeed)
    {
      var seed = new Seed(seedInput);
      var addresses = await GenerateChiotaAddresses(seed);
      return new User
               {
                 Name = null,
                 Seed = seed,
                 ImageUrl = null,
                 StoreSeed = storeSeed,
                 OwnDataAdress = addresses[0].Value,
                 PublicKeyAddress = addresses[1].Value, // + addresses[1].WithChecksum().Checksum.Value,
                 RequestAddress = addresses[2].Value,
                 ApprovedAddress = addresses[3].Value,
                 TangleMessenger = new TangleMessenger(seed),
                 NtruKeyPair = new NtruKex(true).CreateAsymmetricKeyPair(seed.ToString().ToLower(), addresses[0].Value) 
               };
    }

    private static async Task<List<Address>> GenerateChiotaAddresses(Seed seed)
    {
      // addresses can be generated based on each other to make it faster
      var addresses = await Task.Run(() => new AddressGenerator().GetAddresses(seed, SecurityLevel.Medium, 0, 2));
      addresses.Add(Helper.GenerateAddress(addresses[0]));
      addresses.Add(Helper.GenerateAddress(addresses[1]));
      return addresses;
    }
  }
}
