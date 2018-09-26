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
    public ExceptionContactRepository(Exception exception = null)
    {
      this.Exception = exception;
    }

    private Exception Exception { get; }

    /// <inheritdoc />
    public Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
    {
      if (this.Exception != null)
      {
        throw this.Exception;
      }

      throw new MessengerException(ResponseCode.CannotAddContact, new Exception());
    }

    public async Task<ContactInformation> LoadContactInformationByAddressAsync(Address address)
    {
      if (this.Exception != null)
      {
        throw this.Exception;
      }

      throw new MessengerException(ResponseCode.CannotAddContact, new Exception());
    }

    /// <inheritdoc />
    public Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
    {
      throw this.Exception;
    }
  }
}