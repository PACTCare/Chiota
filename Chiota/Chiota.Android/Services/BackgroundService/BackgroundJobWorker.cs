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
using Newtonsoft.Json.Linq;
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

        private static PersistableBundle _parameters;

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

            _parameters = new PersistableBundle();
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
            var jobs = _parameters.GetStringArray("jobs");

            var json = new JObject
            {
                {"job", typeof(T).Namespace + "." + typeof(T).Name + ", " + typeof(T).Assembly.FullName},
                {"data", JsonConvert.SerializeObject(data)}
            };

            if (jobs != null)
            {
                json.Add("id", jobs.Count());
                var list = new List<string>(jobs) {JsonConvert.SerializeObject(json)};
                _parameters.PutStringArray("jobs", list.ToArray());
            }
            else
            {
                json.Add("id", 0);
                _parameters.PutStringArray("jobs", new string[] { JsonConvert.SerializeObject(json) });
            }
        }

        #endregion

        #region Register

        public void Register()
        {
            //First cancel all running jobs.
            Dispose();

            //Add the encryption of the current user.
            _parameters.PutString("encryption", JsonConvert.SerializeObject(UserService.CurrentUser.EncryptionKey));

            var builder = _context.CreateJobInfoBuilder(1)
                .SetPersisted(true)
                .SetMinimumLatency(1000)
                .SetOverrideDeadline(10000)
                .SetRequiredNetworkType(NetworkType.Any)
                .SetExtras(_parameters);

            _jobScheduler.Schedule(builder.Build());
        }

        #endregion

        #region Clear

        public void Clear()
        {
            _parameters = new PersistableBundle();
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