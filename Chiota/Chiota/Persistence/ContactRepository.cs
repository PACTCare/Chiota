using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.Database;
using Pact.Palantir.Entity;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Tangle.Net.Cryptography.Signing;

namespace Chiota.Persistence
{
    public class ContactRepository : AbstractTangleContactRepository
    {
        #region Constructors

        public ContactRepository(IMessenger messenger, ISignatureValidator signatureValidator) : base(messenger, signatureValidator)
        {
        }

        #endregion

        #region Methods

        #region AddContact

        public override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
        {
            var task = Task.Run(() =>
            {
                var contact = new DbContact()
                {
                    ChatAddress = address,
                    PublicKeyAddress = publicKeyAddress,
                    Accepted = accepted
                };

                DatabaseService.Contact.AddObject(contact);
            });
            task.Wait();

            return task;
        }

        #endregion

        #region LoadContacts

        public override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var contacts = DatabaseService.Contact.GetAcceptedContactsByPublicKeyAddress(publicKeyAddress);
                    var list = new List<Contact>();

                    foreach (var item in contacts)
                    {
                        list.Add(new Contact()
                        {
                            ChatAddress = item.ChatAddress,
                            Rejected = !item.Accepted
                        });
                    }

                    return list;
                }
                catch (Exception)
                {
                    return new List<Contact>();
                }
            });
            task.Wait();

            return task;
        }

        #endregion

        #endregion
    }
}
