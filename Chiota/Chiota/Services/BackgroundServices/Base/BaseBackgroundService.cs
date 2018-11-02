using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Services.BackgroundServices.Trigger.Base;

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundService
    {
        #region Properties

        public string Name { get; protected set; }
        public bool IsRepeatable { get; protected set; }

        public List<BaseTrigger> Triggers { get; protected set; }
        public List<ConditionType> Conditions { get; protected set; }

        #endregion

        #region Constructors

        protected BaseBackgroundService()
        {
            Triggers = new List<BaseTrigger>();
            Conditions = new List<ConditionType>();
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background service.
        /// </summary>
        public virtual void Init(params object[] objects)
        {
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Do some clean up for the background service.
        /// </summary>
        public virtual void Dispose()
        {

        }

        #endregion

        #region Run

        /// <summary>
        /// Run the background service.
        /// </summary>
        public abstract Task RunAsync();

        #endregion

        #region PostInit

        /// <summary>
        /// Init the object with default values, if necessary.
        /// </summary>
        /// <returns></returns>
        public bool PostInit()
        {
            //Set default values, if necessary.
            if (string.IsNullOrEmpty(Name))
                Name = Guid.NewGuid().ToString();

            if (Triggers.Count == 0)
                return false;

            return true;
        }

        #endregion

        #endregion
    }
}
