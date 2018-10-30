using System;
using System.Collections.Generic;
using Chiota.Services.BackgroundServices.Trigger.Base;

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundService
    {
        #region Attributes

        protected bool IsRepeatable;

        protected List<BaseTrigger> Triggers;
        protected List<ConditionType> Conditions;

        #endregion

        #region Constructors

        protected BaseBackgroundService(bool isRepeatable)
        {
            IsRepeatable = isRepeatable;

            Triggers = new List<BaseTrigger>();
            Conditions = new List<ConditionType>();
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background service.
        /// </summary>
        public virtual void Init()
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

        #region IsValid

        /// <summary>
        /// Validate the background service object.
        /// </summary>
        /// <returns></returns>
        public virtual bool IsValid()
        {
            if (Triggers.Count == 0)
                return false;

            return true;
        }

        #endregion

        #region Run

        /// <summary>
        /// Run the background service.
        /// </summary>
        public abstract void Run();

        #endregion

        #endregion
    }
}
