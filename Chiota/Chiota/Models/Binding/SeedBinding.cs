using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Chiota.Annotations;
using Chiota.Models.Database.Base;

namespace Chiota.Models.Binding
{
    public class SeedBinding : INotifyPropertyChanged
    {
        #region Attributes

        private List<SeedLineBinding> _lines;

        #endregion

        #region Properties

        public List<SeedLineBinding> Lines
        {
            get => _lines;
            set
            {
                _lines = value;
                OnPropertyChanged(nameof(Lines));
            }
        }

        #endregion

        #region Constructors

        public SeedBinding(string seed)
        {
            //Init the list.
            Lines = new List<SeedLineBinding>();

            //Calculate the length of the seed for the ui.
            var length = seed.Length / 9;
            //var rest = seed.Length % length;

            for (var i = 0; i < length; i++)
                Lines.Add(new SeedLineBinding(seed.Substring(i * length, length)));
        }

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

    public class SeedLineBinding : BaseModel
    {
        #region Attributes

        private List<string> _items;

        #endregion

        #region Properties

        public List<string> Items
        {
            get => _items;
            set
            {
                _items = value;
                OnPropertyChanged(nameof(Items));
            }
        }

        #endregion

        #region Constructors

        public SeedLineBinding(string line)
        {
            //Init the list.
            Items = new List<string>();

            foreach (var item in line.ToCharArray())
                Items.Add(item.ToString());
        }

        #endregion
    }
}
