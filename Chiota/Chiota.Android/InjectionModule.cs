namespace Chiota.Droid
{
  using Autofac;

  using Chiota.Droid.Persistence;
  using Chiota.Droid.Services;
  using Chiota.Messenger.Service;
  using Chiota.Persistence;
  using Chiota.Services;

  /// <inheritdoc />
  public class InjectionModule : Module
  {
    /// <inheritdoc />
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<ClipboardService>().As<IClipboardService>();
      builder.RegisterType<SqlLiteDb>().As<AbstractSqlLiteDb>();
    }
  }
}
