using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Chiota.Services.BackgroundServices.Base;

namespace Chiota.Droid.Services.BackgroundService
{
    [Service(Name = "chiotaapp.chiotaapp.BackgroundService", Permission = "android.permission.BIND_JOB_SERVICE")]
    public class BackgroundService : JobService
    {
        #region OnStartJob

        public override bool OnStartJob(JobParameters jobParameters)
        {
            Task.Run(async () =>
            {
                var id = jobParameters.Extras.GetString("id");
                var job = jobParameters.Extras.GetString("job");
                var assembly = jobParameters.Extras.GetString("assembly");
                var data = jobParameters.Extras.GetString("data");
                var refreshTime = (int)jobParameters.Extras.GetDouble("refreshtime");

                //Create a new instance of the background job.
                var jobType = Type.GetType(job + ", " + assembly);
                if (string.IsNullOrEmpty(id) || jobType == null)
                {
                    JobFinished(jobParameters, false);
                    return;
                }

                BaseBackgroundJob backgroundJob = null;
                if (refreshTime == 0)
                    backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, id);
                else
                    backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, id, TimeSpan.FromMilliseconds(refreshTime));

                if (!string.IsNullOrEmpty(data))
                    backgroundJob.Init(data);
                else
                    backgroundJob.Init();

                await backgroundJob.RunAsync();

                if (backgroundJob.IsRepeatable)
                {
                    await Task.Delay(backgroundJob.RefreshTime);
                    JobFinished(jobParameters, true);
                    return;
                }

                backgroundJob.Dispose();
                JobFinished(jobParameters, false);
            });

            return true;
        }

        #endregion

        #region OnStopJob

        public override bool OnStopJob(JobParameters jobParameters)
        {
            return false;
        }

        #endregion
    }
}