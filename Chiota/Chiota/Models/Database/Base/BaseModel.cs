#region References

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Chiota.Annotations;
using Newtonsoft.Json;
using SQLite;

#endregion

namespace Chiota.Models.Database.Base
{
    public abstract class BaseModel : INotifyPropertyChanged
    {
        #region Properties

        [PrimaryKey, AutoIncrement]
        [JsonProperty("id")]
        public int Id { get; set; }

        #endregion

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
