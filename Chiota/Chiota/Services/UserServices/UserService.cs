using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Messenger.Entity;
using Chiota.Models;
using Tangle.Net.Entity;

namespace Chiota.Services.UserServices
{
    public class UserService
    {
        #region Attributes

        private IUserFactory _userFactory;

        #endregion

        #region Properties

        public static User CurrentUser { get; set; }

        #endregion

        #region Constructors

        public UserService(IUserFactory userFactory)
        {
            _userFactory = userFactory;
        }

        #endregion

        #region Methods

        #region CreateNew

        public async Task CreateNew(UserCreationProperties properties)
        {
            var user = await _userFactory.CreateAsync(properties.Seed, properties.Name);

            SecureStorage.StoreUser(user, properties.Password);
            SetCurrentUser(user);
        }

        #endregion

        #region SetCurrentUser

        /// <summary>
        /// The set current user.
        /// </summary>
        /// <param name="user">
        /// The user.
        /// </param>
        public static void SetCurrentUser(User user)
        {
            CurrentUser = user;
        }

        #endregion

        #region GetCurrentUserAs

        /// <summary>
        /// The get current as.
        /// </summary>
        /// <typeparam name="T">
        /// The derived user type.
        /// </typeparam>
        /// <returns>
        /// The <see cref="T"/>.
        /// </returns>
        public static T GetCurrentUserAs<T>() where T : User
        {
            return CurrentUser as T;
        }

        #endregion

        #endregion
    }
}