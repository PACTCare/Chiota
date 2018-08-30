namespace Chiota.Messenger.Tests.Repository
{
  using System;
  using System.Collections.Generic;
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Usecase;

  using Tangle.Net.Entity;

  /// <summary>
  /// The exception contact repository.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class ExceptionContactRepository : IContactRepository
  {
    /// <inheritdoc />
    public Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      throw new MessengerException(ResponseCode.CannotAddContact, new Exception());
    }

    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      return new ContactInformation
               {
                 ContactAddress = new Address(Hash.Empty.Value),
                 NtruKey = InMemoryContactRepository.NtruKeyPair.PublicKey
               };
    }

    /// <inheritdoc />
    public Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      return null;
    }
  }
}