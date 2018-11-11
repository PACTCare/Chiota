using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.UWP.Services.BackgroundService;
using Newtonsoft.Json;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundWorker : IBackgroundJobWorker
    {
        #region Attributes

        private const string Name = "chiotaapp.chiotaapp.BackgroundService";

        private static List<BaseBackgroundJob> _backgroundJobs;
        private ApplicationTrigger _trigger;

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
        public void Init()
        {
            _isDisposed = false;

            //Register the background service.
            if (IsRegistered())
                Unregister();

            Task.Run(async () => await Register());
        }

        #endregion

        #region Disposed

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Disposed()
        {
            _isDisposed = true;

            //Unregister the background service.
            if (IsRegistered())
                Unregister();

            //Dispose all the jobs.
            foreach (var item in _backgroundJobs)
                item?.Dispose();

            _backgroundJobs?.Clear();
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
            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), jobId);
            backgroundJob.Init();

            _backgroundJobs.Add(backgroundJob);
        }

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// <param name="refreshTime"></param>
        public void Add<T>(string jobId, TimeSpan refreshTime) where T : BaseBackgroundJob
        {
            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), jobId, refreshTime);
            backgroundJob.Init();

            _backgroundJobs.Add(backgroundJob);
        }

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jobId"></param>
        /// <param name="data"></param>
        public void Add<T>(string jobId, object data) where T : BaseBackgroundJob
        {
            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), jobId);
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            _backgroundJobs.Add(backgroundJob);
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
            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), jobId, refreshTime);
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            _backgroundJobs.Add(backgroundJob);
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
            var exist = _backgroundJobs.First(t => t.Id == jobId);
            if (exist != null)
            {
                exist.Dispose();
                _backgroundJobs.Remove(exist);
            }
        }

        #endregion

        #region Register

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        private async Task Register()
        {
            //Update the access to the execution manager.
            BackgroundExecutionManager.RemoveAccess();
            var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

            //Create new background task.
            var builder = new BackgroundTaskBuilder
            {
                Name = Name,
                TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask"
            };

            if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
            {
                _trigger = new ApplicationTrigger();

                //Set the triggers.
                builder.SetTrigger(_trigger);

                //Register the new task.
                var task = builder.Register();
                task.Completed += TaskCompleted;

                await _trigger.RequestAsync();
            }
        }

        #endregion

        #region TaskCompleted

        /// <summary>
        /// Runs after the service is completed.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        protected void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
        {
            //Just return it, if the background service is disposed.
            if (_isDisposed) return;

            //Check, if there exist a background service.
            if (_backgroundJobs.Count == 0)
            {
                Task.Run(async () =>
                {
                    await Task.Delay(default(TimeSpan));
                    await _trigger.RequestAsync();
                });
                return;
            }

            for(var i = 0; i < _backgroundJobs.Count; i++)
            {
                var job = _backgroundJobs[i];
                if (job.IsRunning) continue;

                Task.Run(async () =>
                {
                    job.IsRunning = true;
                    await job.RunAsync();

                    //Remove the current job from the list and add it to the end of the que, if the job is repeatable.
                    //Otherwise, dispose the job.
                    _backgroundJobs.Remove(job);

                    job.IsRunning = false;
                    if (job.IsDisposed) return;

                    if (job.IsRepeatable)
                    {
                        await Task.Delay(job.RefreshTime);
                        _backgroundJobs.Add(job);
                    }
                    else
                        job.Dispose();
                });
            }

            //Repeat it
            Task.Run(async () =>
            {
                await _trigger.RequestAsync();
            });
        }

        #endregion

        #region Unregister

        /// <summary>
        /// Unregister the background service of the app.
        /// </summary>
        private void Unregister()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == Name)
                    task.Value.Unregister(true);
        }

        #endregion

        #region IsRegistered

        /// <summary>
        /// Get information, if the service is already registered.
        /// </summary>
        /// <returns></returns>
        private bool IsRegistered()
        {
            return BackgroundTaskRegistration.AllTasks.Any(task => task.Value.Name == Name);
        }

        #endregion

        #endregion
    }
}
