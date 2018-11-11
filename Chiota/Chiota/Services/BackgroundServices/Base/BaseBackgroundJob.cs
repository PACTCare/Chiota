using System.Threading.Tasks;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundJob
    {
        #region Attributes

        protected ISqlite Sqlite;
        protected INotification Notification;

        #endregion

        #region Properties

        public int Id { get; }

        public bool IsRunning { get; set; }

        public bool IsDisposed { get; private set; }

        #endregion

        #region Constructors

        protected BaseBackgroundJob(int id, ISqlite sqlite, INotification notification)
        {
            IsRunning = false;
            IsDisposed = false;

            Id = id;
            Sqlite = sqlite;
            Notification = notification;
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background job.
        /// </summary>
        public virtual void Init(string data = null)
        {
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Do some clean up for the background job.
        /// </summary>
        public virtual void Dispose()
        {
            IsDisposed = true;
        }

        #endregion

        #region Run

        /// <summary>
        /// Run the background job.
        /// </summary>
        public abstract Task<bool> RunAsync();

        #endregion

        #endregion
    }
}
