using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database.Base;
using Microsoft.EntityFrameworkCore;

namespace Chiota.Services.Database.Base
{
    public class TableRepository<T> : BaseRepository where T : TableModel
    {
       #region Constructors

        /// <summary>
        /// Base constructor of the database Repositories.
        /// Controls the access of the different database tables.
        /// </summary>
        /// <param name="context">Context of the local database.</param>
        protected TableRepository(DatabaseContext context) : base(context)
        {
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
                var models = DatabaseContext.Set<T>().ToList();
                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region GetObjectsAsync

        /// <summary>
        /// Get all objects of the table.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public virtual async Task<List<T>> GetObjectsAsync()
        {
            try
            {
                var models = await DatabaseContext.Set<T>().ToListAsync();
                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

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
                var model = DatabaseContext.Set<T>().Find(id);
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region GetObjectByIdAsync

        /// <summary>
        /// Get specific object by id.
        /// </summary>
        /// <param name="id">Id of the object as integer</param>
        /// <returns>Object of the table</returns>
        public virtual async Task<T> GetObjectByIdAsync(int id)
        {
            try
            {
                var model = await DatabaseContext.Set<T>().FindAsync(id);
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

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
                var state = DatabaseContext.Set<T>().Add(t);
                var result = state.State == EntityState.Added;
                DatabaseContext.SaveChanges();

                if (!result) return null;
                var model = DatabaseContext.Set<T>().Last();
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region AddObjectAsync

        /// <summary>
        /// Add new object to the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful insert as boolean</returns>
        public virtual async Task<T> AddObjectAsync(T t)
        {
            try
            {
                var state = await DatabaseContext.Set<T>().AddAsync(t);
                var result = state.State == EntityState.Added;
                await DatabaseContext.SaveChangesAsync();

                if (!result) return null;
                var model = DatabaseContext.Set<T>().Last();
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

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
                var state = DatabaseContext.Set<T>().Update(t);
                var result = state.State == EntityState.Modified;
                DatabaseContext.SaveChanges();

                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #region UpdateObjectAsync

        /// <summary>
        /// Update specific object of the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful update as boolean</returns>
        public virtual async Task<bool> UpdateObjectAsync(T t)
        {
            try
            {
                var state = DatabaseContext.Set<T>().Update(t);
                var result = state.State == EntityState.Modified;
                await DatabaseContext.SaveChangesAsync();

                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

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
                var models = GetObjects();
                DatabaseContext.Set<T>().RemoveRange(models);
                DatabaseContext.SaveChanges();

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #region DeleteObjectAsync

        /// <summary>
        /// Remove specific object of the table.
        /// </summary>
        /// <param name="id">Id of the object</param>
        /// <returns>Result of successful delete as boolean</returns>
        public virtual async Task<bool> DeleteObjectsAsync()
        {
            try
            {
                var models = await GetObjectsAsync();
                DatabaseContext.Set<T>().RemoveRange(models);
                await DatabaseContext.SaveChangesAsync();

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
                var model = DatabaseContext.Set<T>().Find(id);
                var state = DatabaseContext.Set<T>().Remove(model);
                var result = state.State == EntityState.Deleted;
                DatabaseContext.SaveChanges();

                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #region DeleteObjectAsync

        /// <summary>
        /// Remove specific object of the table.
        /// </summary>
        /// <param name="id">Id of the object</param>
        /// <returns>Result of successful delete as boolean</returns>
        public virtual async Task<bool> DeleteObjectAsync(int id)
        {
            try
            {
                var model = await DatabaseContext.Set<T>().FindAsync(id);
                var state = DatabaseContext.Set<T>().Remove(model);
                var result = state.State == EntityState.Deleted;
                await DatabaseContext.SaveChangesAsync();

                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

        #endregion

        #region QueryObject

        /// <summary>
        /// Select specific object by a given function.
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns>Object of the table</returns>
        protected T QueryObject(Func<T, bool> predicate)
        {
            try
            {
                var model = DatabaseContext.Set<T>().Where(predicate).First();
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region QueryObjects

        /// <summary>
        /// Select list of objects by a given function.
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns>List of the table objects</returns>
        protected List<T> QueryObjects(Func<T, bool> predicate)
        {
            try
            {
                var models = DatabaseContext.Set<T>().Where(predicate).ToList();
                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #endregion
    }
}
