using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices.Base;
using Chiota.UWP.Services.BackgroundService;
using Xamarin.Forms;
using TimeTrigger = Chiota.Services.BackgroundServices.Trigger.TimeTrigger;

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundWorker : IBackgroundWorker
    {
        #region Attributes

        private BaseBackgroundService _backgroundService;
        private List<IBackgroundTrigger> _trigger;
        private List<IBackgroundCondition> _conditions;

        #endregion

        #region Methods

        #region Start

        //Start a background service with the background worker.
        public void Start<T>(params object[] objects) where T : BaseBackgroundService
        {
            //Create an instance of the background service.
            _backgroundService = (T)Activator.CreateInstance(typeof(T));

            //Init the background service.
            _backgroundService.Init(objects);
            _backgroundService.PostInit();

            //Register the background service.
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
                Name = _backgroundService.Name,
                TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask"
            };

            if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
            {
                _trigger = GetTrigger(_backgroundService);
                _conditions = GetConditions(_backgroundService);

                //Set the triggers.
                foreach (var item in _trigger)
                    builder.SetTrigger(item);

                //Set the conditions.
                foreach (var item in _conditions)
                    builder.AddCondition(item);

                //Register the new task.
                var task = builder.Register();
                task.Completed += TaskCompleted;

                //If there is a time trigger in the list, just wait the time, then raise the service.
                for (var i = 0; i < _trigger.Count; i++)
                {
                    if (_trigger[i] is ApplicationTrigger)
                        await ((ApplicationTrigger)_trigger[i]).RequestAsync();
                }
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
            //Run the service asynchronous.
            Task.Run(async () =>
            {
                await _backgroundService.RunAsync();
            });

            //Repeat it, if necessary.
            if (_backgroundService.IsRepeatable)
            {
                var task = Task.Run(async () =>
                {
                    //If there is a time trigger in the list, just wait the time, then raise the service.
                    for (var i = 0; i < _trigger.Count; i++)
                    {
                        if (_trigger[i] is ApplicationTrigger)
                        {
                            var time = ((TimeTrigger)_backgroundService.Triggers[i]).Time;
                            await Task.Delay(time);
                            await((ApplicationTrigger)_trigger[i]).RequestAsync();
                        }
                    }
                });
                task.Wait();
            }
        }

        #endregion

        #region GetTrigger

        /// <summary>
        /// Get the background service triggers.
        /// </summary>
        /// <param name="backgroundService"></param>
        /// <returns></returns>
        private List<IBackgroundTrigger> GetTrigger(BaseBackgroundService backgroundService)
        {
            var list = new List<IBackgroundTrigger>();

            foreach (var item in backgroundService.Triggers)
            {
                switch (item)
                {
                    case TimeTrigger timeTrigger:
                        list.Add(new ApplicationTrigger());
                        break;
                }
            }

            return list;
        }

        #endregion

        #region GetConditions

        /// <summary>
        /// Get the background service conditions.
        /// </summary>
        /// <param name="backgroundService"></param>
        /// <returns></returns>
        private List<IBackgroundCondition> GetConditions(BaseBackgroundService backgroundService)
        {
            var list = new List<IBackgroundCondition>();

            foreach (var item in backgroundService.Conditions)
            {
                switch (item)
                {
                    case ConditionType.InternetAvailable:
                        list.Add(new SystemCondition(SystemConditionType.InternetAvailable));
                        break;
                }
            }

            return list;
        }

        #endregion

        #region Unregister

        /// <summary>
        /// Unregister the background service of the app.
        /// </summary>
        private void Unregister()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == _backgroundService.Name)
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
            return BackgroundTaskRegistration.AllTasks.Any(task => task.Value.Name == _backgroundService.Name);
        }

        #endregion

        #endregion
    }
}
