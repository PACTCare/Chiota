namespace Chiota.TemplateSelector 
{
  using Chiota.CustomCells;
  using Chiota.ViewModels;

  using Xamarin.Forms;

  public class ContactTemplateSelector : DataTemplateSelector
  {
    private readonly DataTemplate approvedTemplate;

    private readonly DataTemplate requestTemplate;

    public ContactTemplateSelector()
    {
      this.approvedTemplate = new DataTemplate(typeof(ApprovedContactViewCell));
      this.requestTemplate = new DataTemplate(typeof(RequestContactViewCell));
    }

    protected override DataTemplate OnSelectTemplate(object item, BindableObject container)
    {
      if (!(item is ContactListViewModel contact))
      {
        return null;
      }

      return contact.Contact.Request ? this.requestTemplate : this.approvedTemplate;
    }
  }
}
