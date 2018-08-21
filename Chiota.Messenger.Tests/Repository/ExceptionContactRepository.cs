namespace Chiota.Messenger.Tests.Repository
{
  using System;
  using System.Diagnostics.CodeAnalysis;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Usecase;

  /// <summary>
  /// The exception contact repository.
  /// </summary>
  [ExcludeFromCodeCoverage]
  internal class ExceptionContactRepository : IContactRepository
  {
    /// <inheritdoc />
    public Task AddContactAsync(Contact contact)
    {
      throw new MessengerException(ResponseCode.CannotAddContact, new Exception());
    }
  }
}