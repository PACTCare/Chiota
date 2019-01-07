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
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
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

        private TableMapping _messageTableMapping;

        private DbUser _user;

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

            _messageTableMapping = new TableMapping(typeof(DbMessage));

            if (data.Length == 0) return;

            foreach (var item in data)
            {
                switch (item)
                {
                    case DbUser user:
                        _user = user;
                        _user.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(_user.Seed.ToLower(), _user.PublicKeyAddress);
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
                var messagesToSend = _database.Query(_messageTableMapping, "SELECT * FROM " + _messageTableMapping.TableName + " WHERE " + nameof(DbMessage.Owner) + "=1 AND " + nameof(DbMessage.Status) + "=0;").Cast<DbMessage>().ToList();

                if (messagesToSend.Count == 0) return true;

                foreach (var message in messagesToSend)
                {
                    DecryptModel(message);

                    var response = await Interactor.ExecuteAsync(new SendMessageRequest
                    {
                        ChatAddress = new Address(message.ChatAddress),
                        ChatKeyAddress = new Address(message.ChatKeyAddress),
                        UserKeyPair = UserService.CurrentUser.NtruKeyPair,
                        UserPublicKeyAddress = new Address(UserService.CurrentUser.PublicKeyAddress),
                        Message = message.Value
                    });

                    if (response.Code == ResponseCode.Success)
                        //Send the message successfully, update the database.
                        message.Status = (int)MessageStatus.Send;
                    else
                        //Send the message successfully, update the database.
                        message.Status = (int)MessageStatus.Failed;

                    message.Date = DateTime.Now;

                    EncryptModel(message);
                    _database.Update(message);
                }

               return true;
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
