using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Classes;

namespace Chiota.Models.BackUp
{
    public class Seed : BaseModel
    {
        #region Attributes

        private List<SeedLine> _lines;

        #endregion

        #region Properties

        public List<SeedLine> Lines
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

        public Seed(string seed)
        {
            //Init the list.
            Lines = new List<SeedLine>();

            //Calculate the length of the seed for the ui.
            var length = seed.Length / 9;
            //var rest = seed.Length % length;

            for (var i = 0; i < length; i++)
                Lines.Add(new SeedLine(seed.Substring(i * length, length)));
        }

        #endregion
    }

    public class SeedLine : BaseModel
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

        public SeedLine(string line)
        {
            //Init the list.
            Items = new List<string>();

            foreach (var item in line.ToCharArray())
                Items.Add(item.ToString());
        }

        #endregion
    }
}
