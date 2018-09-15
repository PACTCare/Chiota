namespace Chiota.Messenger.Tests.Service
{
  using System.Collections.Generic;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  internal class InMemoryAddressGenerator : IAddressGenerator
  {
    /// <inheritdoc />
    public Address GetAddress(Seed seed, int securityLevel, int index)
    {
      return new Address(seed.Value);
    }

    /// <inheritdoc />
    public Address GetAddress(AbstractPrivateKey privateKey)
    {
      return null;
    }

    /// <inheritdoc />
    public List<Address> GetAddresses(Seed seed, int securityLevel, int startIndex, int count)
    {
      return null;
    }
  }
}