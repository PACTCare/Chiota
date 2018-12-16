#region References

using Android.App.Job;
using Android.Content;
using Java.Lang;

#endregion

namespace Chiota.Droid.Services.BackgroundService
{
    public static class BackgroundServiceHelpers
    {
        #region Attributes

        public static readonly string ResultKey = "result";
        public static readonly string JobActionKey = "job_action";

        #endregion

        #region Methods

        #region CreateJobInfoBuilder

        /// <summary>
        /// Helper to initialize the JobInfo.Builder for the JobService, 
        /// initializing the value 
        /// </summary>
        /// <returns>The job info builder.</returns>
        /// <param name="context">Context.</param>
        public static JobInfo.Builder CreateJobInfoBuilder(this Context context, int id)
        {
            var component = context.GetComponentNameForJob<BackgroundService>();
            var builder = new JobInfo.Builder(id, component);
            return builder;
        }

        #endregion

        #region GetComponentNameForJob

        /// <summary>
        /// Get the component name for the job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="context"></param>
        /// <returns></returns>
        public static ComponentName GetComponentNameForJob<T>(this Context context) where T : JobService
        {
            var t = typeof(T);
            var javaClass = Class.FromType(t);
            return new ComponentName(context, javaClass);
        }

        #endregion

        #endregion
    }
}