using System.Threading.Tasks;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundJob
    {
        #region Properties

        public int Id { get; }

        public bool IsRunning { get; set; }

        public bool IsDisposed { get; private set; }

        protected DatabaseService Database { get; }

        protected INotification Notification { get; }

        #endregion

        #region Constructors

        protected BaseBackgroundJob(int id, DatabaseService database, INotification notification)
        {
            Id = id;

            IsRunning = false;
            IsDisposed = false;

            Database = database;
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
