#region References

using System;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Chiota.Services.BackgroundServices.Base;
using Xamarin.Forms;
using Void = Java.Lang.Void;

#endregion

namespace Chiota.Droid.Services.BackgroundService
{
    [Service(Name = "Chiota.Droid.Services.BackgroundService.BackgroundService", Permission = "android.permission.BIND_JOB_SERVICE")]
    public class BackgroundService : JobService
    {
        #region Attributes

        private BackgroundServiceTask _serviceTask;
        private JobParameters _parameters;
        private BackgroundJobScheduler _backgroundJobScheduler;

        #endregion

        #region Constructors

        public BackgroundService()
        {
            // Create an instance of the background job worker, where all background jobs running.
            _backgroundJobScheduler = (BackgroundJobScheduler)Activator.CreateInstance(typeof(BackgroundJobScheduler));
            _backgroundJobScheduler.Init();

            MessagingCenter.Subscribe<BackgroundJobWorker, BackgroundJobSchedulerMessage>(this, "AddContact", (sender, arg) => {
                _backgroundJobScheduler.Add(arg);
            });
        }

        #endregion

        #region Methods

        #region OnStartJob

        /// <summary>
        /// Called, when the job started.
        /// </summary>
        /// <param name="params"></param>
        /// <returns></returns>
        public override bool OnStartJob(JobParameters @params)
        {
            _parameters = @params;
            _serviceTask = new BackgroundServiceTask(this);

            _serviceTask.Execute(_backgroundJobScheduler);

            return true;
        }

        #endregion

        #region OnStopJob

        /// <summary>
        /// Called, if the job is stopped.
        /// </summary>
        /// <param name="params"></param>
        /// <returns></returns>
        public override bool OnStopJob(JobParameters @params)
        {
            if (_serviceTask != null && !_serviceTask.IsCancelled)
            {
                _serviceTask.Cancel(true);
            }
            _serviceTask = null;

            SendBroadcast();

            return false;
        }

        #endregion

        #region SendBroadcast

        /// <summary>
        /// Broadcast the result of the Fibonacci calculation.
        /// </summary>
        private void SendBroadcast()
        {
            var i = new Intent(BackgroundServiceHelpers.JobActionKey);
            BaseContext.SendBroadcast(i);
        }

        #endregion

        #endregion

        #region BackgroundServiceTask

        /// <summary>
        /// Performs a simple Fibonacci calculation for a seed value. 
        /// </summary>
        class BackgroundServiceTask : AsyncTask<BackgroundJobScheduler, Void, BackgroundJobScheduler>
        {
            #region Attributes

            private readonly BackgroundService jobService;

            #endregion

            #region Constructors

            public BackgroundServiceTask(BackgroundService jobService)
            {
                this.jobService = jobService;
            }

            #endregion

            #region Methods

            protected override BackgroundJobScheduler RunInBackground(params BackgroundJobScheduler[] @params)
            {
                var job = @params[0];

                Task.Run(async () =>
                {
                    await job.RunAsync();
                }).Wait();

                return job;
            }

            protected override void OnPostExecute(BackgroundJobScheduler job)
            {
                base.OnPostExecute(job);

                jobService.SendBroadcast();

                if (job.IsDisposed)
                {
                    jobService.JobFinished(jobService._parameters, false);
                    return;
                }

                jobService.OnStartJob(jobService._parameters);
            }

            protected override void OnCancelled()
            {
                jobService.SendBroadcast();

                base.OnCancelled();
            }

            #endregion
        }

        #endregion
    }
}