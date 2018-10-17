namespace Chiota.Services.UserServices
{
  using System.Threading.Tasks;

  using Chiota.Models;

  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.CreateUser;

  using Tangle.Net.Entity;

  /// <inheritdoc />
  public class UserFactory : IUserFactory
  {
    public UserFactory(IUsecaseInteractor<CreateUserRequest, CreateUserResponse> createUserInteractor)
    {
      this.CreateUserInteractor = createUserInteractor;
    }

    private IUsecaseInteractor<CreateUserRequest, CreateUserResponse> CreateUserInteractor { get; }

    /// <inheritdoc />
    public async Task<User> CreateAsync(Seed seed, string name)
    {
      var response = await this.CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = seed });

      return new User
               {
                 Name = name,
                 Seed = seed.Value,
                 ImageHash = null,
                 StoreSeed = true,
                 PublicKeyAddress = response.PublicKeyAddress.Value, 
                 RequestAddress = response.RequestAddress.Value,
                 NtruKeyPair = response.NtruKeyPair
               };
    }
  }
}
