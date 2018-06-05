namespace Chiota.TemplateSelector
{
  using Chiota.CustomCells;
  using Chiota.ViewModels;

  using Xamarin.Forms;

  public class MyDataTemplateSelector : DataTemplateSelector
  {
    public MyDataTemplateSelector()
    {
      // Retain instances!
      this.incomingDataTemplate = new DataTemplate(typeof(IncomingViewCell));
      this.outgoingDataTemplate = new DataTemplate(typeof(OutgoingViewCell));
    }

    protected override DataTemplate OnSelectTemplate(object item, BindableObject container)
    {
      if (!(item is MessageViewModel messageVm))
      {
        return null;
      }

      return messageVm.IsIncoming ? this.incomingDataTemplate : this.outgoingDataTemplate;
    }

    private readonly DataTemplate incomingDataTemplate;
    private readonly DataTemplate outgoingDataTemplate;

  }
}
