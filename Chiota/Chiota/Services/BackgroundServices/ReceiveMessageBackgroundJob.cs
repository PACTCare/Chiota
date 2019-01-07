#region References

using System;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Resources.Localizations;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetContacts;
using Pact.Palantir.Usecase.GetMessages;
using SQLite;
using Tangle.Net.Cryptography.Signing;
using Tangle.Net.Entity;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using Xamarin.Forms;

#endregion

namespace Chiota.Services.BackgroundServices
{
    public class ReceiveMessageBackgroundJob : BaseSecurityBackgroundJob
    {
        #region Attributes

        private INotification _notification;
        private SQLiteConnection _database;

        private TableMapping _contactTableMapping;
        private TableMapping _messageTableMapping;

        private DbUser _user;

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static GetMessagesInteractor Interactor => new GetMessagesInteractor(Messenger, NtruEncryption.Default, NtruEncryption.Key);

        #endregion

        #region Methods

        #region Init

        public override void Init(params object[] data)
        {
            base.Init(data);

            //Init the notification interface.
            _notification = DependencyService.Get<INotification>();
            _database = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            _contactTableMapping = new TableMapping(typeof(DbContact));
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
                //TODO For Future use chat, after refactoring Palantir (Differ contact and chat).
                //Get all accepted contacts of the user.
                var contacts = _database.Query(_contactTableMapping, "SELECT * FROM " + _contactTableMapping.TableName + " WHERE " + nameof(DbContact.Accepted) + "=1 AND " + nameof(DbContact.ChatKeyAddress) + " IS NOT NULL AND " + nameof(DbContact.ContactAddress) + " IS NOT NULL AND " + nameof(DbContact.Name) + " IS NOT NULL;").Cast<DbContact>().ToList();

                //No contacts, no messages.
                if (contacts.Count == 0) return true;

                //Get a random contact of the list to receive new messages.
                var id = new Random().Next(0, contacts.Count - 1);
                var contact = contacts[id];
                DecryptModel(contact);

                //Execute a messages request for the chat.
                var response = await Interactor.ExecuteAsync(
                    new GetMessagesRequest
                    {
                        ChatAddress = new Address(contact.CurrentChatAddress),
                        ChatKeyAddress = new Address(contact.ChatKeyAddress),
                        UserKeyPair = _user.NtruKeyPair
                    });

                if (response.Code == ResponseCode.Success)
                {
                    var messagesCount = _database.Query(_messageTableMapping, "SELECT * FROM " + _messageTableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=?;", Encrypt(response.CurrentChatAddress.Value)).Cast<DbMessage>().ToList();
                    if (messagesCount.Count >= response.Messages.Count) return true;

                    //First update the new chat address.
                    contact.CurrentChatAddress = response.CurrentChatAddress.Value;
                    EncryptModel(contact);
                    _database.Update(contact);

                    DecryptModel(contact);

                    //Insert the new messages into the database.
                    var newMessages = response.Messages.GetRange(messagesCount.Count, response.Messages.Count - messagesCount.Count);

                    foreach (var item in newMessages)
                    {
                        if (item == null) continue;

                        var owner = item.Signature != contact.PublicKeyAddress.Substring(0, 30);

                        //Add the new message to the database and show a notification.
                        var message = new DbMessage()
                        {
                            ChatAddress = response.CurrentChatAddress.Value,
                            ChatKeyAddress = contact.ChatKeyAddress,
                            Value = item.Message,
                            Date = item.Date,
                            Status = (int)MessageStatus.Received,
                            Signature = item.Signature,
                            Owner = owner,
                            ContactId = contact.Id
                        };

                        //Show a notification, if the user is not the sender.
                        if (!owner)
                            _notification.Show(contact.Name, message.Value);

                        EncryptModel(message);
                        _database.Insert(message);
                    }
                    return true;
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
