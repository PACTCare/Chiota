using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Base
{
    public class TableRepository<T> : BaseRepository where T : TableModel
    {
        #region Attributes

        protected TableMapping TableMapping;

        #endregion

        #region Constructors

        /// <summary>
        /// Base constructor of the database Repositories.
        /// Controls the access of the different database tables.
        /// </summary>
        /// <param name="database"></param>
        protected TableRepository(SQLiteConnection database) : base(database)
        {
            database.CreateTable<T>();
            TableMapping = new TableMapping(typeof(T));
        }

        #endregion

        #region Methods

        #region GetObjects

        /// <summary>
        /// Get all objects of the table.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public virtual List<T> GetObjects()
        {
            try
            {
                var models = (IEnumerable<T>)Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + ";");
                return new List<T>(models);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetObjectById

        /// <summary>
        /// Get specific object by id.
        /// </summary>
        /// <param name="id">Id of the object as integer</param>
        /// <returns>Object of the table</returns>
        public virtual T GetObjectById(int id)
        {
            try
            {
                return (T)Database.Get(id, TableMapping);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetLastAddedObject

        /// <summary>
        /// Get the last added object in the database.
        /// </summary>
        /// <returns></returns>
        public virtual T GetLastAddedObject()
        {
            try
            {
                var lastRowId = SQLite3.LastInsertRowid(Database.Handle);
                var last = (T)Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE rowid=" + Convert.ToString(lastRowId) + ";");
                return last;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region AddObject

        /// <summary>
        /// Add new object to the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful insert as boolean</returns>
        public virtual T AddObject(T t)
        {
            try
            {
                Database.Insert(t);
                return GetLastAddedObject();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region UpdateObject

        /// <summary>
        /// Update specific object of the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful update as boolean</returns>
        public virtual bool UpdateObject(T t)
        {
            try
            {
                Database.Update(t);

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

        #region DeleteObjects

        /// <summary>
        /// Remove all objects of the table.
        /// </summary>
        /// <returns>Result of successful delete as boolean</returns>
        public virtual bool DeleteObjects()
        {
            try
            {
                Database.DeleteAll<T>();

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

        #region DeleteObject

        /// <summary>
        /// Remove specific object of the table.
        /// </summary>
        /// <param name="id">Id of the object</param>
        /// <returns>Result of successful delete as boolean</returns>
        public virtual bool DeleteObject(int id)
        {
            try
            {
                Database.Delete<T>(id);

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }       

        #endregion

        #endregion
    }
}
