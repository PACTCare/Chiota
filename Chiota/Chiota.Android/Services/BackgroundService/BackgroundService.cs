using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Gms.Gcm;
using Android.OS;
using Android.Runtime;
using Android.Util;
using Android.Views;
using Android.Widget;
using Chiota.Services.BackgroundServices.Base;
using Task = System.Threading.Tasks.Task;

namespace Chiota.Droid.Services.BackgroundService
{
    [Service(Exported = true, Permission = "com.google.android.gms.permission.BIND_NETWORK_TASK_SERVICE")]
    [IntentFilter(new[] { "com.google.android.gms.gcm.ACTION_TASK_READY" })]
    public class BackgroundService : GcmTaskService
    {
        #region Attributes

        private IBinder binder;

        #endregion

        #region OnRunTask

        public override int OnRunTask(TaskParams jobParameters)
        {
            System.Threading.Tasks.Task.Run(async () => {
                var test = new Notification();
                test.Show("Test", "Test");
                // TODO: Perform background refresh logic here.
                Log.Debug("Background Service", "Background Task Succeeded");
            });

            /*var test = new Notification();
            test.Show("Test", "Test");

            var id = jobParameters.Extras.GetString("id");
            var job = jobParameters.Extras.GetString("job");
            var assembly = jobParameters.Extras.GetString("assembly");
            var data = jobParameters.Extras.GetString("data");
            var refreshTime = (int)jobParameters.Extras.GetDouble("refreshtime");

            //Create a new instance of the background job.
            var jobType = Type.GetType(job + ", " + assembly);
            if (string.IsNullOrEmpty(id) || jobType == null)
                return GcmNetworkManager.ResultFailure;

            Task.Run(async () =>
            {
                BaseBackgroundJob backgroundJob = null;
                if (refreshTime == 0)
                    backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, id);
                else
                    backgroundJob = (BaseBackgroundJob)Activator.CreateInstance(jobType, id, TimeSpan.FromMilliseconds(refreshTime));

                if (!string.IsNullOrEmpty(data))
                    backgroundJob.Init(data);
                else
                    backgroundJob.Init();

                var repeat = await backgroundJob.RunAsync();

                if (backgroundJob.IsRepeatable)
                {
                    await Task.Delay(backgroundJob.RefreshTime);
                    //return GcmNetworkManager.ResultSuccess;
                }

                backgroundJob.Dispose();
                //return GcmNetworkManager.ResultReschedule;
            });*/

            /*if (isrepeatable)
                return GcmNetworkManager.ResultReschedule;
            else
                return GcmNetworkManager.ResultSuccess;*/

            return GcmNetworkManager.ResultSuccess;
        }

        #endregion

        #region OnBind

        public override IBinder OnBind(Intent intent)
        {
            binder = new BackgroundServiceBinder(this);

            return binder;
        }

        #endregion
    }
}
