namespace Chiota.Services.UserServices
{
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Service;
  using Chiota.Models;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;

  using TangleMessenger = Iota.TangleMessenger;

  /// <inheritdoc />
  public class UserFactory : IUserFactory
  {
    /// <inheritdoc />
    public async Task<User> CreateAsync(Seed seed, string name)
    {
      // addresses can be generated based on each other to make it faster
      var addresses = await Task.Run(() => new AddressGenerator().GetAddresses(seed, SecurityLevel.Medium, 0, 1));
      addresses.Add(Helper.GenerateAddress(addresses[0]));

      return new User
               {
                 Name = name,
                 Seed = seed.Value,
                 ImageHash = null,
                 StoreSeed = true,
                 PublicKeyAddress = addresses[0].Value, 
                 RequestAddress = addresses[1].Value,
                 TangleMessenger = new TangleMessenger(seed),
                 NtruKeyPair = new NtruKeyExchange(NTRUParamSets.NTRUParamNames.A2011743).CreateAsymmetricKeyPair(seed.ToString().ToLower(), addresses[0].Value) 
               };
    }
  }
}
