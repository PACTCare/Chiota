#region References

using System;
using System.Collections.Generic;
using System.Linq;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

#endregion

namespace Chiota.Services.Database.Repositories
{
    public class ContactRepository : SecureRepository<DbContact>
    {
        #region Constructors

        public ContactRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetAcceptedContacts

        /// <summary>
        /// Get all accepted contacts of the user.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetAcceptedContacts()
        {
            try
            {
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.Accepted) + "=1;").Cast<DbContact>().ToList();

                for (var i = 0; i < query.Count; i++)
                    query[i] = DecryptModel(query[i]);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetUnacceptedContacts

        /// <summary>
        /// Get all unaccepted contacts of the user.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetUnacceptedContacts()
        {
            try
            {
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.Accepted) + "=0;").Cast<DbContact>().ToList();

                for (var i = 0; i < query.Count; i++)
                    query[i] = DecryptModel(query[i]);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetAcceptedContactsByPublicKeyAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetAcceptedContactsByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", value).Cast<DbContact>().ToList();

                for (var i = 0; i < query.Count; i++)
                    query[i] = DecryptModel(query[i]);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetContactByPublicKeyAddress

        /// <summary>
        /// Get an contact by his public key address of the user.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public DbContact GetContactByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.ChatAddress) + "=?", value) as DbContact;

                DecryptModel(query);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetAcceptedContactByChatAddress

        /// <summary>
        /// Get first object of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public DbContact GetAcceptedContactByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.ChatAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", value) as DbContact;

                DecryptModel(query);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion
    }
}
