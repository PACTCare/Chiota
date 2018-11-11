using System;
using Android.App.Job;
using Android.Content;
using Android.OS;
using Java.Lang;

namespace Chiota.Droid.Services.BackgroundService
{
    public static class JobSchedulerHelpers
    {
        public static readonly int FibonacciJobId = 110;
        public static readonly string FibonacciValueKey = "fibonacci_value";
        public static readonly string FibonacciResultKey = "fibonacci_result";
        public static readonly string FibonacciJobActionKey = "fibonacci_job_action";

        /// <summary>
        /// Helper to initialize the JobInfo.Builder for the Fibonacci JobService, 
        /// initializing the value 
        /// </summary>
        /// <returns>The job info builder for fibonnaci calculation.</returns>
        /// <param name="context">Context.</param>
        /// <param name="value">Value.</param>
        public static JobInfo.Builder CreateJobInfoBuilderForFibonnaciCalculation(this Context context, int value)
        {
            var component = context.GetComponentNameForJob<BackgroundService>();
            JobInfo.Builder builder = new JobInfo.Builder(FibonacciJobId, component)
                                                 .SetFibonacciValue(value);
            return builder;
        }

        public static ComponentName GetComponentNameForJob<T>(this Context context) where T : JobService
        {
            Type t = typeof(T);
            Class javaClass = Class.FromType(t);
            return new ComponentName(context, javaClass);
        }

        public static JobInfo.Builder SetFibonacciValue(this JobInfo.Builder builder, int value)
        {
            var extras = new PersistableBundle();
            extras.PutLong(FibonacciValueKey, value);
            builder.SetExtras(extras);
            return builder;
        }
    }
}