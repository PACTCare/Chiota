﻿using Chiota.Models.Database;

namespace Chiota.Services.UserServices
{
    using System.Threading.Tasks;

    using Chiota.Messenger.Usecase;
    using Chiota.Messenger.Usecase.CreateUser;
    using Chiota.Models;

    using Tangle.Net.Entity;

    /// <inheritdoc />
    public class UserFactory : IUserFactory
    {
        public UserFactory(IUsecaseInteractor<CreateUserRequest, CreateUserResponse> createUserInteractor)
        {
            CreateUserInteractor = createUserInteractor;
        }

        private IUsecaseInteractor<CreateUserRequest, CreateUserResponse> CreateUserInteractor { get; }

        /// <inheritdoc />
        public async Task<User> CreateAsync(Seed seed, string name)
        {
            var response = await CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = seed });

            if (response.Code != ResponseCode.Success)
                return null;

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
