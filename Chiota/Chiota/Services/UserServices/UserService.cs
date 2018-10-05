using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Messenger.Entity;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.CreateUser;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database;
using Chiota.Services.DependencyInjection;
using Tangle.Net.Entity;

namespace Chiota.Services.UserServices
{
    public class UserService
    {
        #region Attributes

        private IUserFactory _userFactory;

        #endregion

        #region Properties

        public static User CurrentUser { get; private set; }

        #endregion

        #region Constructors

        public UserService(IUserFactory userFactory)
        {
            _userFactory = userFactory;
        }

        #endregion

        #region Methods

        #region CreateNew

        /// <summary>
        /// Return a new created user object, which is saved in the database.
        /// </summary>
        /// <param name="properties"></param>
        /// <returns></returns>
        public async Task<bool> CreateNew(UserCreationProperties properties)
        {
            var user = await _userFactory.CreateAsync(properties.Seed, properties.Name);
            var result = await DatabaseService.User.SetObjectAsync(properties.Password, user);
            if (!result)
                return false;

            //Update the database info.
            var info = await DatabaseService.DatabaseInfo.GetObjectAsync();
            info.UserStored = true;
            result = await DatabaseService.DatabaseInfo.SetObjectAsync(info);
            if (!result)
                return false;

            SetCurrentUser(user);

            return true;
        }

        #endregion

        #region Update

        /// <summary>
        /// Update the user in the database, if the password is correct.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<bool> UpdateAsync(string key, User user)
        {
            var result = await DatabaseService.User.GetObjectAsync(key);
            if (result == null) return false;

            DatabaseService.User.RemoveObject(key);
            await DatabaseService.User.SetObjectAsync(key, user);

            SetCurrentUser(result);

            return true;
        }

        #endregion

        #region LogIn

        /// <summary>
        /// Log in with a password as key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public async Task<bool> LogInAsync(string key)
        {
            var result = await DatabaseService.User.GetObjectAsync(key);
            if (result == null) return false;

            SetCurrentUser(result);

            return true;
        }

        #endregion

        #region SetCurrentUser

        /// <summary>
        /// The set current user.
        /// </summary>
        /// <param name="user">
        /// The user.
        /// </param>
        public void SetCurrentUser(User user)
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
        public T GetCurrentUserAs<T>() where T : User
        {
            return CurrentUser as T;
        }

        #endregion

        #endregion
    }
}