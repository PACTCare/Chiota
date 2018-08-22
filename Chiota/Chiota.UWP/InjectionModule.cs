namespace Chiota.UWP
{
  using Autofac;

  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.UWP.Persistence;
  using Chiota.UWP.Services;

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
