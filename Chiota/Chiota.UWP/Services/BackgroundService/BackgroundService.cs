using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices.Base;

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
        public void Register(int id)
        {
            Task.Run(async () =>
            {
                //Update the access to the execution manager.
                BackgroundExecutionManager.RemoveAccess();
                var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

                //Create new background task.
                var builder = new BackgroundTaskBuilder
                {
                    Name = "BackgroundService_" + id,
                    TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask"
                };

                if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
                {
                    _trigger = new ApplicationTrigger();

                    //Set the triggers.
                    builder.SetTrigger(_trigger);
                    builder.AddCondition(new SystemCondition(SystemConditionType.InternetAvailable));

                    //Register the new task.
                    var task = builder.Register();

                    task.Completed += TaskCompleted;

                    await _trigger.RequestAsync();
                }
            });
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
            Task.Run(async () =>
            {
                var result = await BackgroundJob.RunAsync();

                //Update database, because job is finished.
                if (!result)
                {
                    BackgroundJob.Dispose();
                    return;
                }

                //Repeat it.
                await _trigger.RequestAsync();
            }).Wait();
        }

        #endregion

        #endregion
    }
}
