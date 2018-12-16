#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Chiota.Droid.Services.Database;
using Chiota.Models;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
            var jobs = @params.Extras.GetStringArray("jobs");
            var encryption = @params.Extras.GetString("encryption");

            foreach (var item in jobs)
            {
                var job = JObject.Parse(item);

                //Create a new instance of the background job.
                var jobType = Type.GetType((string)job.GetValue("job"));
                if (jobType == null)
                {
                    JobFinished(@params, false);
                    return false;
                }

                var encryptionKey = JsonConvert.DeserializeObject<EncryptionKey>(encryption);
                var backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, (int)job.GetValue("id"), new DatabaseService(new Sqlite(), encryptionKey), new Notification());
                backgroundJob.Init((string)job.GetValue("data"));

                _parameters = @params;
                _serviceTask = new BackgroundServiceTask(this);

                _serviceTask.Execute(backgroundJob);
            }

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

                if (job.IsDisposed)
                {
                    //Remove the job from the parameters.
                    var jobs = jobService._parameters.Extras.GetStringArray("jobs");
                    foreach (var item in jobs)
                    {
                        var json = JObject.Parse(item);
                        if (job.Id == (int) json.GetValue("id"))
                        {
                            var list = new List<string>(jobs);
                            list.Remove(item);
                            jobService._parameters.Extras.PutStringArray("jobs", list.ToArray());
                            break;
                        }
                    }

                    jobs = jobService._parameters.Extras.GetStringArray("jobs");

                    if (jobs.Length == 0)
                    {
                        jobService.JobFinished(jobService._parameters, false);
                        return;
                    }
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