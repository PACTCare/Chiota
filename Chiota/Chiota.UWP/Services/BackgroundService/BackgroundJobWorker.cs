#region References

using Chiota.UWP.Services.BackgroundService;
using System;
using System.Threading.Tasks;
using Chiota.Services.BackgroundServices.Base;
using Windows.ApplicationModel.Background;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(BackgroundJobWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundJobWorker : IBackgroundJobWorker
    {
        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(params object[] data)
        {
            // Create an instance of the background job worker, where all background jobs running.
            var backgroundJobScheduler = (BackgroundJobScheduler)Activator.CreateInstance(typeof(BackgroundJobScheduler));
            backgroundJobScheduler.Init();

            MessagingCenter.Subscribe<BackgroundJobWorker, BackgroundJobSchedulerMessage>(this, "AddContact", (sender, arg) => {
                backgroundJobScheduler.Add(arg);
            });

            // First cancel all running jobs.
            this.Dispose();

            var service = new BackgroundService(backgroundJobScheduler);
            Task.Run(async () => { await service.RegisterAsync(); });
        }

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Dispose()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                task.Value.Unregister(true);
        }

        /// <summary>
        /// Run a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        public void Run<T>(params object[] data)
            where T : BaseBackgroundJob
        {
            var type = typeof(T).Namespace + "." + typeof(T).Name + ", " + typeof(T).Assembly.FullName;

            MessagingCenter.Send(this, "AddContact", new BackgroundJobSchedulerMessage(type, data));
        }
    }
}