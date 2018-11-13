using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices.Base;
using Java.Util.Jar;

namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundService
    {
        #region Attributes

        private ApplicationTrigger _trigger;

        #endregion

        #region Properties

        public BaseBackgroundJob BackgroundJob { get; }

        #endregion

        #region Constructors

        public BackgroundService(BaseBackgroundJob backgroundJob)
        {
            BackgroundJob = backgroundJob;
        }

        #endregion

        #region Methods

        #region Register

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        public async Task RegisterAsync()
        {
            //Update the access to the execution manager.
            BackgroundExecutionManager.RemoveAccess();
            var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

            //Create new background task.
            var builder = new BackgroundTaskBuilder
            {
                Name = "BackgroundService_" + BackgroundJob.Id,
                TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask",
                IsNetworkRequested = true
            };

            if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
            {
                _trigger = new ApplicationTrigger();

                //Set the triggers.
                builder.SetTrigger(_trigger);

                //Register the new task.
                var task = builder.Register();

                task.Progress += TaskProgress;
                task.Completed += TaskCompleted;

                await _trigger.RequestAsync();
            }
        }

        #endregion TaskProgress

        protected void TaskProgress(BackgroundTaskRegistration sender, BackgroundTaskProgressEventArgs args)
        {
        }

        #region

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
            /*if (_isDisposed) return;

            for (var i = 0; i < _backgroundJobs.Count; i++)
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
            }*/

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
                if (task.Value.Name == "BackgroundService_" + BackgroundJob.Id)
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
            return BackgroundTaskRegistration.AllTasks.Any(task => task.Value.Name == "BackgroundService_" + BackgroundJob.Id);
        }

        #endregion

        #endregion
    }
}
