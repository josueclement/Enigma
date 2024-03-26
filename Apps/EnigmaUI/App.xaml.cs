using System;
using System.Reflection;
using System.Windows;
using Carbon.Themes;

namespace EnigmaUI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        try
        {
            base.OnStartup(e);
            CarbonThemeManager.Init("Dark");
            new AppBootstrapper().Run();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"{Assembly.GetExecutingAssembly().GetName().Name} fatal error:\r\n\r\n {ex}");
            Environment.Exit(1);
        }
    }
}