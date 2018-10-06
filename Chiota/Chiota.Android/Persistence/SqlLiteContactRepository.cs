using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;

namespace Chiota.Droid.Persistence
{
    using System;
    using System.IO;
    using System.Threading.Tasks;
    using Chiota.Messenger.Entity;
    using Chiota.Messenger.Service;
    using Chiota.Persistence;


    using Tangle.Net.Cryptography.Signing;

    public class SqlLiteContactRepository : AbstractSqlLiteContactRepository
    {
        /// <inheritdoc />
        public SqlLiteContactRepository(IMessenger messenger, ISignatureValidator signatureValidator)
            : base(messenger, signatureValidator)
        {
        }

        public override Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
        {
            throw new NotImplementedException();
        }

        public override Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
        {
            throw new NotImplementedException();
        }
    }
}