using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices.Base;
using Chiota.UWP.Services.BackgroundService;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundWorker : IBackgroundWorker
    {
        #region Attributes

        private const string Name = "Chiota.BackgroundTask";
        private ApplicationTrigger _trigger;

        #endregion

        #region Methods

        #region Start

        public void Start()
        {
            //Register the new task.
            if (IsRegistered())
                Unregister();

            Task.Run(async () => await Register());
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
                builder.SetTrigger(_trigger);

                //Register the new task.
                var task = builder.Register();
                task.Completed += TaskCompleted;

                await _trigger.RequestAsync();
            }
        }

        #endregion

        #region TaskCompleted

        protected abstract void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args);

        #endregion

        #region Unregister

        /// <summary>
        /// Unregister the background task of the app.
        /// </summary>
        private void Unregister()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == Name)
                    task.Value.Unregister(true);
        }

        #endregion

        #region IsRegistered

        private bool IsRegistered()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == Name)
                    return true;

            return false;
        }

        #endregion

        #endregion
    }
}
