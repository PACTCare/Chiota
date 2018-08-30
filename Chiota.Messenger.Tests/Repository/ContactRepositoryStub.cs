namespace Chiota.Messenger.Tests.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Repository;

  using Tangle.Net.Repository;

  /// <summary>
  /// The contact repository stub.
  /// </summary>
  internal class ContactRepositoryStub : AbstractTangleContactRepository
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="ContactRepositoryStub"/> class.
    /// </summary>
    /// <param name="iotaRepository">
    /// The iota repository.
    /// </param>
    public ContactRepositoryStub(IIotaRepository iotaRepository)
      : base(iotaRepository)
    {
    }

    /// <summary>
    /// The add contact async.
    /// </summary>
    /// <param name="address">
    /// The address.
    /// </param>
    /// <param name="accepted">
    /// The accepted.
    /// </param>
    /// <param name="publicKeyAddress">
    /// The public key address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      throw new NotImplementedException();
    }

    /// <summary>
    /// The load contacts async.
    /// </summary>
    /// <param name="publicKeyAddress">
    /// The public key address.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      throw new NotImplementedException();
    }
  }
}