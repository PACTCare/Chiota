using System;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Media;
using Android.OS;
using Android.Support.V4.App;
using Android.Util;
using Chiota.Services;
using Chiota.Services.BackgroundServices.Base;
using Xamarin.Forms;

namespace Chiota.Droid.Services.BackgroundService
{
    /// <summary>
    /// Calculates the Fibonacci number for a given seed value in the 
    /// background. When the Fibonacci number is calculated, this service
    /// will broadcast an intent with the action set to 
    /// <code>JobScheduleSample.FibonacciJob.RESULTS</code>.
    /// </summary>
    [Service(Name = "Chiota.Droid.Services.BackgroundService.BackgroundService", Permission = "android.permission.BIND_JOB_SERVICE")]
    public class BackgroundService : JobService
    {
        public static readonly string TAG = typeof(BackgroundService).FullName;
        long fibonacciValue;
        BackgroundServiceTask calculator;
        JobParameters parameters;

        public BackgroundService()
        {
        }

        public override bool OnStartJob(JobParameters @params)
        {
            var test = new Notification();
            test.Show("Test", "1");

            Task.Delay(TimeSpan.FromSeconds(5)).Wait();

            fibonacciValue = @params.Extras.GetLong(JobSchedulerHelpers.FibonacciValueKey, -1);
            if (fibonacciValue < 0)
            {
                Log.Debug(TAG, "Invalid value - must be > 0.");
                return false;
            }

            parameters = @params;
            calculator = new BackgroundServiceTask(this);

            calculator.Execute(fibonacciValue);
            return true; // No more work to do!
        }

        public override bool OnStopJob(JobParameters @params)
        {
            Log.Debug(TAG, "System halted the job.");
            if (calculator != null && !calculator.IsCancelled)
            {
                calculator.Cancel(true);
            }
            calculator = null;


            BroadcastResults(-1);

            return false; // Don't reschedule the job.
        }


        /// <summary>
        /// Broadcast the result of the Fibonacci calculation.
        /// </summary>
        /// <param name="result">Result.</param>
        void BroadcastResults(long result)
        {
            Intent i = new Intent(JobSchedulerHelpers.FibonacciJobActionKey);
            i.PutExtra(JobSchedulerHelpers.FibonacciResultKey, result);
            BaseContext.SendBroadcast(i);
        }


        /// <summary>
        /// Performs a simple Fibonacci calculation for a seed value. 
        /// </summary>
        class BackgroundServiceTask : AsyncTask<long, Java.Lang.Void, long>
        {
            readonly BackgroundService jobService;
            long fibonacciValue = -1;

            public BackgroundServiceTask(BackgroundService jobService)
            {
                this.jobService = jobService;
            }

            long GetFibonacciFor(long value)
            {
                if (value == 0) 
                {
                    return 0;
                }
                if ((value == 1) || (value == 2))
                {
                    return 1;
                }

                long result = 0;
                long n1 = 0;
                long n2 = 1;
                for (long i = 2; i <= value; i++)
                {
                    result = n1 + n2;
                    n1 = n2;
                    n2 = result;
                }

                return result;
            }

            protected override long RunInBackground(params long[] @params)
            {
                fibonacciValue = -1;
                long value = @params[0];
                return GetFibonacciFor(value);
            }

            protected override void OnPostExecute(long result)
            {

                base.OnPostExecute(result);

                fibonacciValue = result;

                jobService.BroadcastResults(result);

                //jobService.JobFinished(jobService.parameters, false);
                jobService.OnStartJob(jobService.parameters);

                Log.Debug(TAG, "Finished with fibonacci calculation: " + result);

            }

            protected override void OnCancelled()
            {
                Log.Debug(TAG, "Job was cancelled.");
                jobService.BroadcastResults(-1);
                base.OnCancelled();
            }

        }
    }
}