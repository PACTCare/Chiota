namespace Chiota.Messenger.Tests.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;

  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Repository;

  internal class ContactRepositoryStub : AbstractTangleContactRepository
  {
    public ContactRepositoryStub(IIotaRepository iotaRepository, ISignatureValidator signatureValidator)
      : base(iotaRepository, signatureValidator)
    {
    }

    public override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      throw new NotImplementedException();
    }

    public override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      throw new NotImplementedException();
    }
  }
}