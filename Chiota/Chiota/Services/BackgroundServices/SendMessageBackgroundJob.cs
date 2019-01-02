#region References

using System;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Entity;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetMessages;
using Pact.Palantir.Usecase.SendMessage;
using SQLite;
using Tangle.Net.Entity;
using Xamarin.Forms;

#endregion

namespace Chiota.Services.BackgroundServices
{
    public class SendMessageBackgroundJob : BaseSecurityBackgroundJob
    {
        #region Attributes

        private SQLiteConnection _database;

        private DbUser _user;
        private DbMessage _message;

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static SendMessageInteractor Interactor => new SendMessageInteractor(Messenger, NtruEncryption.Default, NtruEncryption.Key);

        #endregion

        #region Methods

        #region Init

        public override void Init(params object[] data)
        {
            base.Init(data);

            //Init the notification interface.
            _database = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            if (data.Length == 0) return;

            foreach (var item in data)
            {
                switch (item)
                {
                    case DbUser user:
                        _user = user;
                        _user.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(_user.Seed.ToLower(), _user.PublicKeyAddress);
                        break;
                    case DbMessage message:
                        _message = message;
                        break;
                }
            }
        }

        #endregion

        #region Run

        public override async Task<bool> RunAsync()
        {
            try
            {
                var response = await Interactor.ExecuteAsync(new SendMessageRequest
                {
                    ChatAddress = new Address(_message.ChatAddress),
                    ChatKeyAddress = new Address(_message.ChatKeyAddress),
                    UserKeyPair = UserService.CurrentUser.NtruKeyPair,
                    UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                    Message = _message.Value
                });

                if (response.Code == ResponseCode.Success)
                    //Send the message successfully, update the database.
                    _message.Status = (int) MessageStatus.Send;
                else
                    //Send the message successfully, update the database.
                    _message.Status = (int)MessageStatus.Failed;

                EncryptModel(_message);
                _database.Update(_message);

                return false;
            }
            catch (Exception)
            {
                //Ignore
                return true;
            }
        }

        #endregion

        #endregion
    }
}
