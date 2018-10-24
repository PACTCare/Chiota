using Windows.ApplicationModel.Background;

namespace RuntimeComponent.UWP
{
    public sealed class BackgroundTask : IBackgroundTask
    {
        #region Attributes

        private BackgroundTaskDeferral _taskDeferral;

        #endregion

        #region Methods

        #region Run

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            _taskDeferral = taskInstance.GetDeferral();

            //Run background task.

            _taskDeferral.Complete();
        }

        #endregion

        #endregion
    }
}
