using System;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Media;
using Android.OS;
using Android.Support.V4.App;
using Android.Util;
using Chiota.Droid.Services.Database;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Newtonsoft.Json;
using SQLite;
using Xamarin.Forms;
using Void = Java.Lang.Void;

namespace Chiota.Droid.Services.BackgroundService
{
    [Service(Name = "Chiota.Droid.Services.BackgroundService.BackgroundService", Permission = "android.permission.BIND_JOB_SERVICE")]
    public class BackgroundService : JobService
    {
        #region Attributes

        private BackgroundServiceTask _serviceTask;
        private JobParameters _parameters;

        #endregion

        #region Constructors

        public BackgroundService()
        {
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
            var job = @params.Extras.GetString("job");
            var assembly = @params.Extras.GetString("assembly");
            var data = @params.Extras.GetString("data");
            var encryption = @params.Extras.GetString("encryption");

            //Create a new instance of the background job.
            var jobType = Type.GetType(job + ", " + assembly);
            if (jobType == null)
            {
                JobFinished(@params, false);
                return false;
            }

            var encryptionKey = JsonConvert.DeserializeObject<EncryptionKey>(encryption);
            var backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, new DatabaseService(new Sqlite(), encryptionKey), new Notification());
            backgroundJob.Init(data);

            _parameters = @params;
            _serviceTask = new BackgroundServiceTask(this);

            _serviceTask.Execute(backgroundJob);

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
        class BackgroundServiceTask : AsyncTask<BaseBackgroundJob, Void, BaseBackgroundJob>
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

            protected override BaseBackgroundJob RunInBackground(params BaseBackgroundJob[] @params)
            {
                var job = @params[0];

                Task.Run(async () =>
                {
                    var result = await job.RunAsync();

                    //Update database, because job is finished.
                    if (!result)
                        job.Dispose();
                }).Wait();

                return job;
            }

            protected override void OnPostExecute(BaseBackgroundJob job)
            {
                base.OnPostExecute(job);

                jobService.SendBroadcast();

                if(job.IsDisposed)
                    jobService.JobFinished(jobService._parameters, false);
                else
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