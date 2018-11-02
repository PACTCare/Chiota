using System;
using System.Collections.Generic;
using System.Linq;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class ContactRepository : TableRepository<DbContact>
    {
        #region Constructors

        public ContactRepository(SQLiteConnection database) : base(database)
        {
        }

        #endregion

        #region GetPendingContactsAddress

        /// <summary>
        /// Get all pending contacts of the user.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetPendingContacts()
        {
            try
            {
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.Accepted) + "=0;").Cast<DbContact>().ToList();
                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
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
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", publicKeyAddress).Cast<DbContact>().ToList();
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
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.ChatAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", chatAddress) as DbContact;
                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetContactsOrderByAcceptedDesc

        /// <summary>
        /// Get all objects of the table order by accepted desc.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetContactsOrderByAcceptedDesc()
        {
            try
            {
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " ORDER BY " + nameof(DbContact.Accepted) + " DESC;").Cast<DbContact>().ToList();
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
