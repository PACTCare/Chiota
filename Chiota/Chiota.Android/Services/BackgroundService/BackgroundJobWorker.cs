#region References

using System;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Chiota.Droid.Services.BackgroundService;
using Chiota.Services.BackgroundServices.Base;
using Xamarin.Forms;

#endregion

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

            //First cancel all running jobs.
            Dispose();

            var builder = _context.CreateJobInfoBuilder(1)
                .SetPersisted(true)
                .SetMinimumLatency(1000)
                .SetOverrideDeadline(10000)
                .SetRequiredNetworkType(NetworkType.Any);

            _jobScheduler.Schedule(builder.Build());
        }

        #endregion

        #region Run

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        public void Run<T>(params object[] data) where T : BaseBackgroundJob
        {
            var type = typeof(T).Namespace + "." + typeof(T).Name + ", " + typeof(T).Assembly.FullName;

            MessagingCenter.Send(this, "Add", new BackgroundJobSchedulerMessage(type, data));
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