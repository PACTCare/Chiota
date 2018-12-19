#region References

using System;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.Iota;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetMessages;
using Tangle.Net.Entity;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

#endregion

namespace Chiota.Services.BackgroundServices
{
    /*public class ChatMessageBackgroundJob : BaseBackgroundJob
    {
        #region Attributes

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static GetMessagesInteractor Interactor => new GetMessagesInteractor(Messenger, NtruEncryption.Default, NtruEncryption.Key);

        //private DbUser User;

        private IAsymmetricKeyPair _chatKeyPair;

        private DbUser _user;
        private DbContact _contact;

        #endregion

        #region Constructors

        public ChatMessageBackgroundJob(int id, DatabaseService database, INotification notification) : base(id, database, notification)
        {
        }

        #endregion

        #region Methods

        #region Init

        public override void Init(params object[] data)
        {
            base.Init(data);

            if (string.IsNullOrEmpty(data)) return;
            var json = JArray.Parse(data);
            _user = JsonConvert.DeserializeObject<DbUser>(JsonConvert.SerializeObject(json[0]));
            _contact = JsonConvert.DeserializeObject<DbContact>(JsonConvert.SerializeObject(json[1]));
            _user.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(_user.Seed.ToLower(), _user.PublicKeyAddress);
        }

        #endregion

        #region Run

        public override async Task<bool> RunAsync()
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5));

                //Execute a messages request for the chat.
                var response = await Interactor.ExecuteAsync(
                    new GetMessagesRequest
                    {
                        ChatAddress = new Address(_contact.ChatAddress),
                        ChatKeyPair = _chatKeyPair,
                        ChatKeyAddress = new Address(_contact.ChatKeyAddress),
                        UserKeyPair = _user.NtruKeyPair
                    });

                if (response.Code == ResponseCode.Success)
                {
                    var messagesCount = Database.Message.GetMessagesCountByPublicKeyAddress(_contact.PublicKeyAddress);
                    if (messagesCount <= response.Messages.Count) return true;

                    _contact.ChatAddress = response.CurrentChatAddress.Value;
                    _chatKeyPair = response.ChatKeyPair;

                    //Update the chat address for the chat.
                    Database.Contact.UpdateObject(_contact);

                    var newMessages = response.Messages.GetRange(messagesCount, response.Messages.Count - messagesCount);

                    foreach (var item in newMessages)
                    {
                        if (item == null)
                            return false;

                        var owner = item.Signature != _contact.PublicKeyAddress.Substring(0, 30);
                        //Add the new message to the database and show a notification.
                        var message = new DbMessage()
                        {
                            ChatAddress = _contact.ChatAddress,
                            Value = item.Message,
                            Date = item.Date,
                            Signature = item.Signature,
                            Owner = owner
                        };

                        //Show a notification, if the user is not the sender.
                        if(!message.Owner)
                            Notification.Show(_contact.Name, message.Value);

                        Database.Message.AddObject(message);

                        await Task.Delay(TimeSpan.FromSeconds(1));
                    }

                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                //Ignore
                return false;
            }
        }

        #endregion

        #endregion
    }*/
}
