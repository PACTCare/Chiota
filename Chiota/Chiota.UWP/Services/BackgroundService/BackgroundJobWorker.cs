using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Base;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.UserServices;
using Chiota.UWP.Services.BackgroundService;
using Chiota.UWP.Services.Database;
using Newtonsoft.Json;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundJobWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundJobWorker : IBackgroundJobWorker
    {
        #region Methods

        #region Init

        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(params object[] data)
        {
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Dispose()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                    task.Value.Unregister(true);
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="id"></param>
        /// <param name="data"></param>
        public void Add<T>(int id, params object[] data) where T : BaseBackgroundJob
        {
            if (IsRegistered(id))
                Unregister(id);

            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), new DatabaseService(new Sqlite(), UserService.CurrentUser.EncryptionKey), new Notification());
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            var service = new BackgroundService(backgroundJob);
            service.Register(id);
        }

        #endregion

        #region Remove

        /// <summary>
        /// Remove a background job by his id.
        /// </summary>
        /// <param name="id"></param>
        public void Remove(int id)
        {
            if (IsRegistered(id))
                Unregister(id);
        }

        #endregion

        #region Unregister

        /// <summary>
        /// Unregister the background service of the app.
        /// </summary>
        private void Unregister(int id)
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == "BackgroundService_" + id)
                    task.Value.Unregister(true);
        }

        #endregion

        #region IsRegistered

        /// <summary>
        /// Get information, if the service is already registered.
        /// </summary>
        /// <returns></returns>
        private bool IsRegistered(int id)
        {
            return BackgroundTaskRegistration.AllTasks.Any(task => task.Value.Name == "BackgroundService_" + id);
        }

        #endregion

        #endregion
    }
}
