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
using Chiota.Base;
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
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="id"></param>
        /// <param name="data"></param>
        public void Add<T>(int id, params object[] data) where T : BaseBackgroundJob
        {
            var jobs = _jobScheduler.AllPendingJobs;
            foreach (var item in jobs)
                if (item.Id == id)
                    Remove(id);

            //Add the new background job.
            var jobParameters = new PersistableBundle();
            jobParameters.PutString("job", typeof(T).Namespace + "." + typeof(T).Name);
            jobParameters.PutString("assembly", typeof(T).Assembly.FullName);
            jobParameters.PutString("data", JsonConvert.SerializeObject(data));
            jobParameters.PutString("encryption", JsonConvert.SerializeObject(UserService.CurrentUser.EncryptionKey));

            var builder = _context.CreateJobInfoBuilder(id)
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
            _jobScheduler.Cancel(id);
        }

        #endregion

        #region Dispose

        public void Dispose()
        {
            _jobScheduler.CancelAll();
        }

        #endregion

        #endregion
    }
}