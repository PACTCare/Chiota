using SQLite;

namespace Chiota.Models.Database
{
    public class SqLiteContacts
    {
        [PrimaryKey, AutoIncrement]
        public int Id { get; set; }

        [MaxLength(100)]
        public string ChatAddress { get; set; }

        // to make it unique if mulitple accounts on device
        public string PublicKeyAddress { get; set; }

        public bool Accepted { get; set; }
    }
}
