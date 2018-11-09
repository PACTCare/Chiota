using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Gms.Gcm;
using Android.OS;
using Chiota.Droid.Services.BackgroundService;
using Chiota.Services.BackgroundServices.Base;
using Newtonsoft.Json;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.Droid.Services.BackgroundService
{
    public class BackgroundWorker : IBackgroundWorker
    {
        #region Attributes

        private static Context _context;

        private static List<BaseBackgroundJob> _backgroundJobs;
        private bool _isDisposed;

        #endregion

        #region Constructors

        public BackgroundWorker()
        {
            _backgroundJobs = new List<BaseBackgroundJob>();
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(Context context)
        {
            _isDisposed = false;
            _context = context;
        }

        #endregion

        #region Dispose

        public void Disposed()
        {
            _isDisposed = true;

            /*//Dispose all the jobs.
            foreach (var item in _backgroundJobs)
                item?.Dispose();

            _backgroundJobs?.Clear();*/
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        public void Add<T>(string jobId) where T : BaseBackgroundJob
        {
            Schedule<T>(jobId, null, TimeSpan.FromMilliseconds(0));
        }

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// <param name="refreshTime"></param>
        public void Add<T>(string jobId, TimeSpan refreshTime) where T : BaseBackgroundJob
        {
            Schedule<T>(jobId, null, refreshTime);
        }

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// <param name="data"></param>
        public void Add<T>(string jobId, object data) where T : BaseBackgroundJob
        {
            Schedule<T>(jobId, data, TimeSpan.FromMilliseconds(0));
        }

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// /// <param name="data"></param>
        /// <param name="refreshTime"></param>
        public void Add<T>(string jobId, object data, TimeSpan refreshTime) where T : BaseBackgroundJob
        {
            Schedule<T>(jobId, data, refreshTime);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Remove a background job by his id.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        public void Remove<T>(string jobId) where T : BaseBackgroundJob
        {
            /*var exist = _backgroundJobs.First(t => t.Id == jobId);
            if (exist != null)
            {
                exist.Dispose();
                _backgroundJobs.Remove(exist);
            }*/
        }

        #endregion

        #region Schedule

        /// <summary>
        /// Schedule the new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// <param name="data"></param>
        /// <param name="refreshTime"></param>
        private void Schedule<T>(string jobId, object data, TimeSpan refreshTime) where T : BaseBackgroundJob
        {
            //Prepare the refresh time.
            if (refreshTime > TimeSpan.FromMinutes(1))
                refreshTime = refreshTime - TimeSpan.FromMinutes(1);
            else
                refreshTime = TimeSpan.FromMilliseconds(0);

            var jobParameters = new Bundle();
            jobParameters.PutString("id", jobId);
            jobParameters.PutString("job", typeof(T).Namespace + "." + typeof(T).Name);
            jobParameters.PutString("assembly", typeof(T).Assembly.FullName);
            jobParameters.PutString("data", JsonConvert.SerializeObject(data));
            jobParameters.PutDouble("refreshtime", refreshTime.TotalMilliseconds);

            var pt = new PeriodicTask.Builder()
                .SetPeriod(1800) // in seconds; minimum is 30 seconds
                .SetService(Java.Lang.Class.FromType(typeof(BackgroundService)))
                .SetTag("chiotaapp.chiotaapp")
                .SetRequiredNetwork(0)
                .SetExtras(jobParameters)
                .Build();

            GcmNetworkManager.GetInstance(_context).Schedule(pt);
        }

        #endregion

        #endregion
    }
}
