namespace Chiota.Messenger.Entity
{
  public class Contact : ContactInformation
  {
    public string Name { get; set; }

    public string ImageHash { get; set; }

    public string ChatAddress { get; set; }

    public string ChatKeyAddress { get; set; }

    public string PublicKeyAddress { get; set; }

    public bool Request { get; set; }

    public bool Rejected { get; set; }
  }
}