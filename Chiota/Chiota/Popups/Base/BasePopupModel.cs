#region References

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Chiota.Annotations;

#endregion

namespace Chiota.Popups.Base
{
    public abstract class BasePopupModel : INotifyPropertyChanged
    {
        #region PropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        [NotifyPropertyChangedInvocator]
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
