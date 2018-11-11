using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Chiota.Droid.Services.BackgroundService;
using Chiota.Droid.Services.Database;
using Chiota.Extensions;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.UserServices;
using Newtonsoft.Json;
using SQLite;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundJobWorker))]
namespace Chiota.Droid.Services.BackgroundService
{
    public class BackgroundJobWorker : IBackgroundJobWorker
    {
        #region Attributes

        private static Context _context;
        private static JobScheduler _jobScheduler;
        private static SQLiteConnection _database;

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Init the background jobs.
        /// </summary>
        /// <param name="data"></param>
        public void Init(params object[] data)
        {
            //Set the instance of the context and scheduler.
            _context = (Context)data[0];
            _jobScheduler = (JobScheduler)data[1];

            //Get the database connection.
            _database = new Sqlite().GetDatabaseConnection();
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        public void Add<T>(params object[] data) where T : BaseBackgroundJob
        {
            var job = new DbBackgroundJob()
            {
                Name = typeof(T).Name,
                Status = BackgroundJobStatus.Created.ToString(),
                Assembly = typeof(T).Assembly.FullName,
                Type = typeof(T).Namespace + "." + typeof(T).Name,
                Parameter = JsonConvert.SerializeObject(data)
            };

            //Add the new background job.
            _database.CreateTable<DbBackgroundJob>();
            _database.Insert(job.EncryptObject(UserService.CurrentUser.EncryptionKey));

            var lastRowId = SQLite3.LastInsertRowid(_database.Handle);
            var mapping = new TableMapping(typeof(DbBackgroundJob));
            job = (DbBackgroundJob)_database.FindWithQuery(mapping, "SELECT * FROM " + mapping.TableName + " WHERE rowid=" + Convert.ToString(lastRowId) + ";");

            var jobParameters = new PersistableBundle();
            jobParameters.PutInt("id", job.Id);
            jobParameters.PutString("job", typeof(T).Namespace + "." + typeof(T).Name);
            jobParameters.PutString("assembly", typeof(T).Assembly.FullName);
            jobParameters.PutString("data", JsonConvert.SerializeObject(data));
            jobParameters.PutString("encryption", JsonConvert.SerializeObject(UserService.CurrentUser.EncryptionKey));

            var builder = _context.CreateJobInfoBuilder(job.Id)
                .SetPersisted(true)
                .SetMinimumLatency(1000)
                .SetOverrideDeadline(10000)
                .SetRequiredNetworkType(NetworkType.Any)
                .SetExtras(jobParameters);

            _jobScheduler.Schedule(builder.Build());
        }

        #endregion

        #region Remove

        public void Remove(int id)
        {
            try
            {
                _database.CreateTable<DbBackgroundJob>();
                _database.Delete<DbBackgroundJob>(id);
            }
            catch (Exception)
            {
                //Ignore
            }
        }

        #endregion

        #region Dispose

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        #endregion

        #endregion
    }
}